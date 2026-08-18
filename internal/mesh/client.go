// Package mesh implements the replica↔replica HTTP/2 mesh with internal mTLS (mesh-role certs only):
// lazily-dialed per-directed-pair connection pools (round-robin, grow-to-max), and connID-checked
// stream delivery. When a public connection lands on a node that is NOT the phone's owner, the entry
// node bridges to the owner over the mesh; the owner verifies the connID against its live phone
// connection before dialing back to the phone.
package mesh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
)

// ErrNoOwner is returned when the owner rejects the stream (stale route / connID mismatch).
var ErrNoOwner = errors.New("mesh: owner rejected the stream")

// Stream is a bidirectional splice to the owner node: Read pulls phone→client bytes, Write pushes
// client→phone bytes.
type Stream interface {
	io.ReadWriteCloser
}

// Client dials peer nodes over the mesh and opens connID-checked streams. It holds per-peer pools of
// HTTP/2 clients (round-robin), each backed by its own transport/connection.
type Client struct {
	tlsConf  func() *tls.Config // hot-swappable mesh-role client cert
	poolSize int
	poolMax  int

	mu    sync.Mutex
	pools map[string]*peerPool // peer advertise addr → pool
}

// NewClient builds the mesh client. tlsConf returns the current mesh-role client tls.Config (rotated).
func NewClient(tlsConf func() *tls.Config, poolSize, poolMax int) *Client {
	if poolSize < 1 {
		poolSize = 4
	}
	if poolMax < poolSize {
		poolMax = poolSize
	}
	return &Client{tlsConf: tlsConf, poolSize: poolSize, poolMax: poolMax, pools: map[string]*peerPool{}}
}

type peerPool struct {
	addr    string
	clients []*http.Client
	next    atomic.Uint64
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
	}
	return p
}

// newH2Client builds one HTTP/2 client backed by its own transport (so N clients ≈ N connections,
// round-robin spreading load).
func (c *Client) newH2Client() *http.Client {
	tr := &http2.Transport{
		TLSClientConfig: c.tlsConf(),
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
		resp.Body.Close()
		_ = pw.Close()
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
