package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Backend is invoked for each dial-back data stream: it reads client→phone bytes and writes phone→client
// bytes (the opaque splice to the phone's local target; an echo in tests).
type Backend func(stream io.ReadWriteCloser)

// Client is the HTTP/2 phone control client. It holds a hot-swappable identity (rotated via the mTLS
// POST /api/v1/issue exchange in Renew, not a control frame) and opens dial-back data streams to a
// caller-supplied backend.
type Client struct {
	dialAddr     string
	controlHost  string
	tunnelDomain string
	caPool       *x509.CertPool
	backend      Backend
	logger       *slog.Logger

	mu    sync.Mutex
	ident *Identity
	cert  *tls.Certificate

	tr *http.Transport
	hc *http.Client

	dialBackTimeout time.Duration

	enrollHost     string
	silenceTimeout time.Duration
	sleep          func(context.Context, time.Duration) error
	renewing       atomic.Bool

	dialTimeout      time.Duration
	moveFallbackWait time.Duration

	life  context.Context
	stop  context.CancelFunc
	conns sync.WaitGroup
}

type connTracker struct {
	mu   sync.Mutex
	conn net.Conn
}

func (t *connTracker) track(conn net.Conn) {
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
}

func (t *connTracker) take() net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn := t.conn
	t.conn = nil
	return conn
}

// New builds a control client that dials dialAddr, negotiates TLS with SNI/Host controlHost (trusting
// caPool), presents ident as the mTLS client cert, serves dial-back streams to backend, and renews via
// the mTLS POST /api/v1/issue endpoint (needing tunnelDomain to request <name>.<tunnelDomain>).
func New(dialAddr, enrollHost, controlHost, tunnelDomain string, caPool *x509.CertPool, ident *Identity, backend Backend, opts ...Option) (*Client, error) {
	c := &Client{
		dialAddr: dialAddr, controlHost: controlHost, tunnelDomain: tunnelDomain,
		caPool: caPool, backend: backend, ident: ident, logger: slog.Default(),
		dialBackTimeout: defaultDialBackTimeout,
		enrollHost:      enrollHost, silenceTimeout: wire.ControlSilenceTimeout, sleep: sleepCtx,
		dialTimeout: defaultControlDialTimeout, moveFallbackWait: defaultMoveFallbackWait,
	}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	cert, err := ident.tlsCertificate()
	if err != nil {
		return nil, err
	}
	c.cert = &cert
	c.tr = newMTLSTransport(dialAddr, controlHost, caPool, c.dialTimeout, c.currentCert, func(net.Conn) {})
	c.life, c.stop = context.WithCancel(context.Background())
	c.hc = &http.Client{Transport: c.tr}
	return c, nil
}

type Option func(*Client) error

func WithLogger(l *slog.Logger) Option {
	return func(c *Client) error {
		if l == nil {
			return errors.New("client: nil logger")
		}
		c.logger = l
		return nil
	}
}

var errControlSilence = errors.New("client: no control frame within the silence timeout; connection treated as dead")

func WithControlSilenceTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("client: control silence timeout must be positive")
		}
		c.silenceTimeout = d
		return nil
	}
}

func WithControlDialTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("client: control dial timeout must be positive")
		}
		c.dialTimeout = d
		return nil
	}
}

func WithMoveFallbackWait(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("client: MOVE fallback wait must be positive")
		}
		c.moveFallbackWait = d
		return nil
	}
}

func (c *Client) dropConn(t *connTracker) {
	if conn := t.take(); conn != nil {
		c.closeLogged("control connection", conn)
	}
}

// Close releases the control client's pooled TLS connections. Call it once Run has returned.
func (c *Client) Close() {
	c.stop()
	c.conns.Wait()
	c.tr.CloseIdleConnections()
}

var errNotHTTP2 = errors.New("client: server did not negotiate HTTP/2 (ALPN h2)")

const (
	defaultControlDialTimeout = 10 * time.Second
	defaultMoveFallbackWait   = time.Second
)

// newMTLSTransport builds an HTTP/2 transport that dials dialAddr, negotiates TLS with SNI/Host
// controlHost (trusting caPool), and presents the identity cert returned by getCert as the mTLS client
// cert (getCert is re-invoked per handshake, so a rotated identity is picked up on reconnect).
func newMTLSTransport(dialAddr, controlHost string, caPool *x509.CertPool, dialTimeout time.Duration, getCert func() *tls.Certificate, onConn func(net.Conn)) *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Transport{
		Protocols:       &protocols,
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: &tls.Config{
				ServerName: controlHost, RootCAs: caPool, MinVersion: tls.VersionTLS12,
				NextProtos:           []string{"h2"},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert(), nil },
			}}
			conn, err := d.DialContext(ctx, network, dialAddr)
			if err != nil {
				return nil, err
			}
			h2, err := requireH2(conn)
			if err != nil {
				return nil, err
			}
			onConn(h2)
			return h2, nil
		},
	}
}

func requireH2(conn net.Conn) (net.Conn, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, errors.Join(errNotHTTP2, conn.Close())
	}
	return conn, nil
}

func (c *Client) currentCert() *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

// Identity returns the client's current (possibly renewed) identity.
func (c *Client) Identity() *Identity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ident
}

// Run opens the control connection and serves it until ctx is cancelled or the connection drops.
func (c *Client) Run(ctx context.Context) error {
	next, _, err := c.serveConn(ctx, c.dialAddr)
	for next != nil {
		next, err = c.move(ctx, next)
	}
	return err
}

func (c *Client) move(ctx context.Context, addrs []string) ([]string, error) {
	for _, addr := range c.moveTargets(addrs) {
		next, opened, err := c.serveConn(ctx, addr)
		if opened {
			return next, err
		}
		c.logger.Debug("control connection after a MOVE failed", "addr", addr, "err", err)
		if ctx.Err() != nil {
			return nil, err
		}
	}
	next, opened, err := c.serveConn(ctx, c.dialAddr)
	if !opened || next == nil {
		return nil, err
	}
	if serr := c.sleep(ctx, c.moveFallbackWait); serr != nil {
		return nil, fmt.Errorf("client: wait before following the fallback connection's MOVE: %w", serr)
	}
	return next, nil
}

func (c *Client) moveTargets(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		host, port, err := net.SplitHostPort(a)
		if err != nil || host == "" || port == "" {
			c.logger.Warn("invalid MOVE address from the server (skipped)", "addr", a, "err", err)
			continue
		}
		out = append(out, a)
	}
	return out
}

func (c *Client) serveConn(ctx context.Context, addr string) ([]string, bool, error) {
	tracked := &connTracker{}
	tr := newMTLSTransport(addr, c.controlHost, c.caPool, c.dialTimeout, c.currentCert, tracked.track)
	cctx, cancel := context.WithCancel(ctx)
	stopOnClose := context.AfterFunc(c.life, cancel)
	pr, pw := io.Pipe()
	var (
		wdMu         sync.Mutex
		ended, quiet bool
	)
	silent := func() bool {
		wdMu.Lock()
		defer wdMu.Unlock()
		return quiet
	}
	watchdog := time.AfterFunc(c.silenceTimeout, func() {
		wdMu.Lock()
		defer wdMu.Unlock()
		if ended || quiet {
			return
		}
		quiet = true
		c.dropConn(tracked)
		cancel()
		pw.CloseWithError(errControlSilence)
	})
	finish := func() {
		watchdog.Stop()
		wdMu.Lock()
		ended = true
		wdMu.Unlock()
		stopOnClose()
		cancel()
		c.dropConn(tracked)
		tr.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, "https://"+c.controlHost+"/api/v1/control", pr)
	if err != nil {
		finish()
		return nil, false, fmt.Errorf("client: build the control request for %s: %w", addr, err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		pw.CloseWithError(err)
		finish()
		if silent() {
			return nil, false, errControlSilence
		}
		return nil, false, fmt.Errorf("client: control request to %s: %w", addr, err)
	}
	if resp.StatusCode != http.StatusOK {
		c.closeLogged("control response body", resp.Body)
		c.closeLogged("control request body", pw)
		finish()
		return nil, false, errors.New("client: control connect rejected: " + resp.Status)
	}
	// Deterministic cancellation: closing the body/pipe unblocks the frame read and any in-flight
	// control write immediately, without relying on the transport's own ctx propagation timing.
	stop := context.AfterFunc(cctx, func() {
		c.closeLogged("control response body", resp.Body)
		pw.CloseWithError(cctx.Err())
	})
	watchdog.Reset(c.silenceTimeout)
	moves := make(chan []string, 1)
	done := make(chan error, 1)
	var movedAway atomic.Bool
	c.conns.Add(1)
	go func() {
		defer c.conns.Done()
		err := c.pump(ctx, resp.Body, pw, watchdog, silent, moves, &movedAway)
		if err != nil {
			err = fmt.Errorf("client: control connection to %s: %w", addr, err)
		}
		stop()
		c.closeLogged("control response body", resp.Body)
		c.closeLogged("control request body", pw)
		finish()
		if movedAway.Load() {
			c.logMovedAwayEnd(addr, err)
		}
		done <- err
	}()
	select {
	case next := <-moves:
		return next, true, nil
	case err := <-done:
		select {
		case next := <-moves:
			return next, true, nil
		default:
		}
		return nil, true, err
	}
}

func (c *Client) logMovedAwayEnd(addr string, err error) {
	if err == nil || errors.Is(err, io.EOF) {
		c.logger.Debug("moved-away control connection ended", "addr", addr, "err", err)
		return
	}
	c.logger.Warn("moved-away control connection ended", "addr", addr, "err", err)
}

func (c *Client) pump(base context.Context, body io.Reader, w io.Writer, watchdog *time.Timer, silent func() bool, moves chan<- []string, movedAway *atomic.Bool) error {
	for {
		ct, payload, err := readControlFrame(body)
		if err != nil {
			if silent() {
				return errControlSilence
			}
			if base.Err() != nil {
				return nil
			}
			return err
		}
		watchdog.Reset(c.silenceTimeout)
		switch ct {
		case wire.CtrlOpen:
			go c.handleOpen(base, payload)
		case wire.CtrlPing:
			c.sendControl(w, wire.CtrlPong, nil)
		case wire.CtrlRenewNudge:
			go c.renew(base, payload)
		case wire.CtrlMove:
			var mv wire.MovePayload
			if err := json.Unmarshal(payload, &mv); err != nil {
				c.logger.Warn("malformed MOVE payload from the server (ignored)", "err", err)
				continue
			}
			if len(mv.Addrs) == 0 {
				c.logger.Warn("MOVE without addresses from the server (ignored)")
				continue
			}
			select {
			case moves <- mv.Addrs:
				movedAway.Store(true)
			default:
				c.logger.Debug("MOVE ignored: this connection already moved")
			}
		}
	}
}

// sendControl writes one control frame to the server.
func (c *Client) sendControl(w io.Writer, t wire.ControlType, payload any) {
	frame, err := wire.EncodeControl(t, payload)
	if err != nil {
		c.logger.Warn("control frame encode failed", "type", t, "err", err)
		return
	}
	if _, err := w.Write(frame); err != nil {
		c.logger.Debug("control frame write failed", "type", t, "err", err)
	}
}

func (c *Client) closeLogged(what string, cl io.Closer) {
	if err := cl.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Debug("close failed", "what", what, "err", err)
	}
}

// readControlFrame reads one length-framed control frame ([type:1][len:4 BE][payload]) from r.
func readControlFrame(r io.Reader) (wire.ControlType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > 1<<20 {
		return 0, nil, errors.New("client: control frame too large")
	}
	frame := make([]byte, 5+int(n))
	copy(frame, hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return 0, nil, err
	}
	return wire.DecodeControl(frame)
}
