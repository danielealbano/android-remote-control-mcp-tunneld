// Package mesh implements the replica↔replica HTTP/2 mesh with internal mTLS (mesh-role certs only):
// lazily-dialed per-directed-pair connection pools (round-robin, fixed-size, reaped when idle).
package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var errPeerNotHTTP2 = errors.New("mesh: peer did not negotiate HTTP/2 (ALPN h2)")

// Recorder is the consumer-side observability surface the mesh client needs: it reports each per-peer
// pool's size when the pool is first created (satisfied by metrics.PromRecorder).
type Recorder interface {
	MeshPool(peer string, size int)
}

// Option configures the mesh Client.
type Option func(*Client)

// WithRecorder wires a Recorder so pool sizes are exported.
func WithRecorder(r Recorder) Option { return func(c *Client) { c.rec = r } }

// Mesh connection-health defaults: with no frames for readIdle the transport PINGs the peer and
// closes the connection if no PONG arrives within pingTimeout — a black-holed owner node can never
// pin an entry-side goroutine indefinitely (the pooled client redials on next use). dialTimeout
// bounds the TCP+TLS dial of a NEW connection to an unresponsive address.
const (
	meshReadIdleTimeout = 15 * time.Second
	meshPingTimeout     = 10 * time.Second
	meshDialTimeout     = 10 * time.Second
)

const meshControlTimeout = 10 * time.Second

func WithControlTimeout(d time.Duration) Option { return func(c *Client) { c.controlTimeout = d } }

// Client dials peer nodes over the mesh. It holds per-peer pools of
// HTTP/2 clients (round-robin), each backed by its own transport/connection.
type Client struct {
	tlsConf     func() *tls.Config // hot-swappable mesh-role client cert
	poolSize    int
	rec         Recorder
	readIdle    time.Duration // PING health cadence (see meshReadIdleTimeout)
	pingTimeout time.Duration
	dialTimeout time.Duration

	controlTimeout time.Duration

	mu    sync.Mutex
	pools map[string]*peerPool // peer advertise addr → pool
}

// WithHealthTimeouts overrides the PING-health / dial bounds (tests).
func WithHealthTimeouts(readIdle, ping, dial time.Duration) Option {
	return func(c *Client) { c.readIdle, c.pingTimeout, c.dialTimeout = readIdle, ping, dial }
}

// NewClient builds the mesh client. tlsConf returns the current mesh-role client tls.Config (rotated).
func NewClient(tlsConf func() *tls.Config, poolSize int, opts ...Option) *Client {
	if poolSize < 1 {
		poolSize = 4
	}
	c := &Client{
		tlsConf: tlsConf, poolSize: poolSize, pools: map[string]*peerPool{},
		readIdle: meshReadIdleTimeout, pingTimeout: meshPingTimeout, dialTimeout: meshDialTimeout,
		controlTimeout: meshControlTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type peerPool struct {
	addr    string
	clients []*http.Client
	next    atomic.Uint64
	lastUse atomic.Int64 // unix nanos of the last use of this pool (reap bookkeeping)
	active  atomic.Int64 // in-flight streams held through this pool (a pool with active>0 is never reaped)
}

func (c *Client) pool(peer string) *peerPool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pools[peer]
	if p == nil {
		p = &peerPool{addr: peer}
		for range c.poolSize {
			p.clients = append(p.clients, c.newH2Client())
		}
		c.pools[peer] = p
		if c.rec != nil {
			c.rec.MeshPool(peer, len(p.clients))
		}
	}
	p.lastUse.Store(time.Now().UnixNano())
	// Count this acquisition under c.mu so the increment is atomic with map membership vs the reaper
	// (which also holds c.mu): the pool can never be reaped between this lookup and the increment.
	p.active.Add(1)
	return p
}

// Run reaps per-peer pools that have been idle for reapAfter (closing their pooled connections and
// zeroing the pool-size gauge), until ctx is done. A reaped peer's pool is lazily re-created. Wired onto the server errgroup so idle pools never accumulate across peer churn.
func (c *Client) Run(ctx context.Context, reapAfter time.Duration) error {
	if reapAfter <= 0 {
		reapAfter = 10 * time.Minute
	}
	ticker := time.NewTicker(reapAfter / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cutoff := time.Now().Add(-reapAfter).UnixNano()
			c.mu.Lock()
			for peer, p := range c.pools {
				if p.lastUse.Load() >= cutoff {
					continue
				}
				if p.active.Load() > 0 {
					continue // carrying live streams — CloseIdleConnections would orphan the busy conn
				}
				delete(c.pools, peer)
				for _, hc := range p.clients {
					hc.CloseIdleConnections()
				}
				if c.rec != nil {
					c.rec.MeshPool(peer, 0)
				}
			}
			c.mu.Unlock()
		}
	}
}

// newH2Client builds one HTTP/2 client backed by its own transport (so N clients ≈ N connections,
// round-robin spreading load), with PING health + a bounded dial so a dead peer never pins a caller.
func (c *Client) newH2Client() *http.Client {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	cfg := c.tlsConf()
	tr := &http.Transport{
		Protocols:       &protocols,
		HTTP2:           &http.HTTP2Config{SendPingTimeout: c.readIdle, PingTimeout: c.pingTimeout},
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: c.dialTimeout}, Config: cfg}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return requirePeerH2(conn)
		},
	}
	return &http.Client{Transport: tr}
}

func requirePeerH2(conn net.Conn) (net.Conn, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, errors.Join(errPeerNotHTTP2, conn.Close())
	}
	return conn, nil
}

// Control posts a mesh control RPC to peer over the per-peer mTLS H2 pool and returns the decoded
// response. Short request/response (not a splice); the pool's active-count guards it against reaping
// for the request's duration.
func (c *Client) Control(ctx context.Context, peer string, req ControlRequest) (_ ControlResponse, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.controlTimeout)
	defer cancel()
	p := c.pool(peer) // active++
	defer p.active.Add(-1)
	hc := p.clients[int(p.next.Add(1))%len(p.clients)]

	body, err := json.Marshal(req)
	if err != nil {
		return ControlResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer+"/api/v1/mesh/control", bytes.NewReader(body))
	if err != nil {
		return ControlResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(httpReq)
	if err != nil {
		return ControlResponse{}, fmt.Errorf("mesh control %s: %w", peer, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("mesh control %s: close response: %w", peer, cerr))
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return ControlResponse{}, fmt.Errorf("mesh control %s: status %d", peer, resp.StatusCode)
	}
	var out ControlResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return ControlResponse{}, err
	}
	return out, nil
}
