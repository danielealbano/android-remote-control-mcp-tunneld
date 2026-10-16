package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
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

	sendMu sync.Mutex
	sendW  io.Writer // control request-body writer (phone→server frames)

	dialBackTimeout time.Duration

	enrollHost     string
	silenceTimeout time.Duration
	sleep          func(context.Context, time.Duration) error
	renewing       atomic.Bool

	connMu sync.Mutex
	conn   net.Conn
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
	c.tr = newMTLSTransport(dialAddr, controlHost, caPool, c.currentCert, c.trackConn)
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

func (c *Client) trackConn(conn net.Conn) {
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
}

func (c *Client) dropConn() {
	c.connMu.Lock()
	conn := c.conn
	c.conn = nil
	c.connMu.Unlock()
	if conn != nil {
		c.closeLogged("control connection", conn)
	}
}

// Close releases the control client's pooled TLS connections. Call it once Run has returned.
func (c *Client) Close() {
	c.tr.CloseIdleConnections()
}

var errNotHTTP2 = errors.New("client: server did not negotiate HTTP/2 (ALPN h2)")

// newMTLSTransport builds an HTTP/2 transport that dials dialAddr, negotiates TLS with SNI/Host
// controlHost (trusting caPool), and presents the identity cert returned by getCert as the mTLS client
// cert (getCert is re-invoked per handshake, so a rotated identity is picked up on reconnect).
func newMTLSTransport(dialAddr, controlHost string, caPool *x509.CertPool, getCert func() *tls.Certificate, onConn func(net.Conn)) *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Transport{
		Protocols:       &protocols,
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
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
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
		c.dropConn()
		cancel()
		pw.CloseWithError(errControlSilence)
	})
	defer func() {
		watchdog.Stop()
		wdMu.Lock()
		ended = true
		wdMu.Unlock()
	}()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, "https://"+c.controlHost+"/api/v1/control", pr)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		pw.CloseWithError(err)
		if silent() {
			return errControlSilence
		}
		return err
	}
	defer c.closeLogged("control response body", resp.Body)
	defer c.closeLogged("control request body", pw)
	if resp.StatusCode != http.StatusOK {
		return errors.New("client: control connect rejected: " + resp.Status)
	}
	// Deterministic cancellation: closing the body/pipe unblocks the frame read and any in-flight
	// control write immediately, without relying on the transport's own ctx propagation timing.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-rctx.Done():
			c.closeLogged("control response body", resp.Body)
			pw.CloseWithError(rctx.Err())
		case <-watchDone:
		}
	}()
	c.setSend(pw)
	watchdog.Reset(c.silenceTimeout)

	for {
		ct, payload, err := readControlFrame(resp.Body)
		if err != nil {
			if silent() {
				return errControlSilence
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		watchdog.Reset(c.silenceTimeout)
		switch ct {
		case wire.CtrlOpen:
			go c.handleOpen(ctx, payload)
		case wire.CtrlPing:
			c.sendControl(wire.CtrlPong, nil)
		case wire.CtrlRenewNudge:
			go c.renew(ctx, payload)
		}
	}
}

func (c *Client) setSend(w io.Writer) {
	c.sendMu.Lock()
	c.sendW = w
	c.sendMu.Unlock()
}

// sendControl writes one control frame to the server (serialized).
func (c *Client) sendControl(t wire.ControlType, payload any) {
	frame, err := wire.EncodeControl(t, payload)
	if err != nil {
		c.logger.Warn("control frame encode failed", "type", t, "err", err)
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.sendW == nil {
		return
	}
	if _, err := c.sendW.Write(frame); err != nil {
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
