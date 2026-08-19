// Package mesh implements the replica↔replica HTTP/2 mesh with internal mTLS (mesh-role certs only):
// lazily-dialed per-directed-pair connection pools (round-robin, fixed-size, reaped when idle), and
// connID-checked stream delivery. When a public connection lands on a node that is NOT the phone's owner, the entry
// node bridges to the owner over the mesh; the owner verifies the connID against its live phone
// connection before dialing back to the phone.
package mesh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// ErrNoOwner is returned when the owner rejects the stream (stale route / connID mismatch).
var ErrNoOwner = errors.New("mesh: owner rejected the stream")

// Stream is a bidirectional splice to the owner node: Read pulls phone→client bytes, Write pushes
// client→phone bytes.
type Stream interface {
	io.ReadWriteCloser
}

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

// Client dials peer nodes over the mesh and opens connID-checked streams. It holds per-peer pools of
// HTTP/2 clients (round-robin), each backed by its own transport/connection.
type Client struct {
	tlsConf     func() *tls.Config // hot-swappable mesh-role client cert
	poolSize    int
	rec         Recorder
	readIdle    time.Duration // PING health cadence (see meshReadIdleTimeout)
	pingTimeout time.Duration
	dialTimeout time.Duration

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
	lastUse atomic.Int64 // unix nanos of the last OpenStream through this pool (reap bookkeeping)
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
	return p
}

// Run reaps per-peer pools that have been idle for reapAfter (closing their pooled connections and
// zeroing the pool-size gauge), until ctx is done. A reaped peer's pool is lazily re-created on the
// next OpenStream. Wired onto the server errgroup so idle pools never accumulate across peer churn.
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
	tr := &http2.Transport{
		TLSClientConfig: c.tlsConf(),
		ReadIdleTimeout: c.readIdle,
		PingTimeout:     c.pingTimeout,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: c.dialTimeout}, Config: cfg}
			return d.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr}
}

// OpenStream dials peer and opens a connID-checked mesh stream for (tunnel, connID, streamID). The
// far side verifies connID against its live phone connection before bridging.
func (c *Client) OpenStream(ctx context.Context, peer, tunnel, connID, streamID string) (io.ReadWriteCloser, error) {
	p := c.pool(peer)
	hc := p.clients[int(p.next.Add(1))%len(p.clients)]

	pr, pw := io.Pipe() // request body: entry→owner (client→phone bytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer+"/mesh", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Tunnel", tunnel)
	req.Header.Set("X-Conn-Id", connID)
	req.Header.Set("X-Stream-Id", streamID)

	resp, err := hc.Do(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("mesh: dial %s: %w", peer, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		if resp.StatusCode == http.StatusUnprocessableEntity {
			return nil, ErrDuplicateStream
		}
		return nil, ErrNoOwner
	}
	return &clientStream{pw: pw, resp: resp}, nil
}

type clientStream struct {
	pw   *io.PipeWriter
	resp *http.Response
	once sync.Once
}

func (s *clientStream) Read(p []byte) (int, error)  { return s.resp.Body.Read(p) }
func (s *clientStream) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *clientStream) Close() error {
	s.once.Do(func() {
		_ = s.pw.Close()
		_ = s.resp.Body.Close()
	})
	return nil
}
