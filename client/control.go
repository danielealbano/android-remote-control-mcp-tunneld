package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Backend is invoked for each dial-back data stream: it reads client→phone bytes and writes phone→client
// bytes (the opaque splice to the phone's local target; an echo in tests).
type Backend func(stream io.ReadWriteCloser)

// Client is the HTTP/2 phone control client. It holds a hot-swappable identity (rotated via the mTLS
// POST /issue exchange in Renew, not a control frame) and opens dial-back data streams to a
// caller-supplied backend.
type Client struct {
	dialAddr     string
	controlHost  string
	tunnelDomain string
	caPool       *x509.CertPool
	backend      Backend

	mu    sync.Mutex
	ident *Identity
	cert  *tls.Certificate

	tr *http2.Transport
	hc *http.Client

	sendMu sync.Mutex
	sendW  io.Writer // control request-body writer (phone→server frames)
}

// New builds a control client that dials dialAddr, negotiates TLS with SNI/Host controlHost (trusting
// caPool), presents ident as the mTLS client cert, serves dial-back streams to backend, and renews via
// the mTLS POST /issue endpoint (needing tunnelDomain to request <name>.<tunnelDomain>).
func New(dialAddr, controlHost, tunnelDomain string, caPool *x509.CertPool, ident *Identity, backend Backend) (*Client, error) {
	c := &Client{
		dialAddr: dialAddr, controlHost: controlHost, tunnelDomain: tunnelDomain,
		caPool: caPool, backend: backend, ident: ident,
	}
	cert, err := ident.tlsCertificate()
	if err != nil {
		return nil, err
	}
	c.cert = &cert
	c.tr = newMTLSTransport(dialAddr, controlHost, caPool, c.currentCert)
	c.hc = &http.Client{Transport: c.tr}
	return c, nil
}

// Close releases the control client's pooled TLS connections. Call it once Run has returned.
func (c *Client) Close() {
	c.tr.CloseIdleConnections()
}

// newMTLSTransport builds an HTTP/2 transport that dials dialAddr, negotiates TLS with SNI/Host
// controlHost (trusting caPool), and presents the identity cert returned by getCert as the mTLS client
// cert (getCert is re-invoked per handshake, so a rotated identity is picked up on reconnect).
func newMTLSTransport(dialAddr, controlHost string, caPool *x509.CertPool, getCert func() *tls.Certificate) *http2.Transport {
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: controlHost, RootCAs: caPool, MinVersion: tls.VersionTLS12,
				NextProtos:           []string{"h2"},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert(), nil },
			}}
			return d.DialContext(ctx, network, dialAddr)
		},
	}
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
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.controlHost+"/control", pr)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	defer func() { _ = pw.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New("client: control connect rejected: " + resp.Status)
	}
	c.setSend(pw)

	for {
		frame, err := readControlFrame(resp.Body)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ct, payload, derr := wire.DecodeControl(frame)
		if derr != nil {
			continue
		}
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
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.sendW == nil {
		return
	}
	_, _ = c.sendW.Write(frame)
}

// readControlFrame reads one length-framed v2 control frame ([type:1][len:4 BE][payload]) from r.
func readControlFrame(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > 1<<20 {
		return nil, errors.New("client: control frame too large")
	}
	frame := make([]byte, 5+int(n))
	copy(frame, hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return nil, err
	}
	return frame, nil
}
