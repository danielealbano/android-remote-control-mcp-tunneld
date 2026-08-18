package client

import (
	"context"
	"crypto/ecdsa"
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

// Client is the HTTP/2 phone control client. It holds a hot-swappable identity (rotated by CERT_PUSH)
// and opens dial-back data streams to a caller-supplied backend.
type Client struct {
	dialAddr    string
	controlHost string
	caPool      *x509.CertPool
	backend     Backend

	mu        sync.Mutex
	ident     *Identity
	cert      *tls.Certificate
	pendingID *ecdsa.PrivateKey // fresh identity key awaiting a renewal CERT_PUSH
	pendingTL *ecdsa.PrivateKey // fresh public key awaiting a renewal CERT_PUSH

	hc *http.Client

	sendMu sync.Mutex
	sendW  io.Writer // control request-body writer (phone→server frames)
}

// New builds a control client that dials dialAddr, negotiates TLS with SNI/Host controlHost (trusting
// caPool), presents ident as the mTLS client cert, and serves dial-back streams to backend.
func New(dialAddr, controlHost string, caPool *x509.CertPool, ident *Identity, backend Backend) (*Client, error) {
	c := &Client{dialAddr: dialAddr, controlHost: controlHost, caPool: caPool, backend: backend, ident: ident}
	cert, err := ident.tlsCertificate()
	if err != nil {
		return nil, err
	}
	c.cert = &cert
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: c.controlHost, RootCAs: c.caPool, MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2"},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return c.currentCert(), nil
				},
			}}
			return d.DialContext(ctx, network, c.dialAddr)
		},
	}
	c.hc = &http.Client{Transport: tr}
	return c, nil
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
			c.sendControl(wire.CtrlRenewRequest, nil)
		case wire.CtrlRenewChallenge:
			c.submitRenewal(payload)
		case wire.CtrlCertPush:
			c.installCerts(payload)
		case wire.CtrlError:
			// A structured server error (e.g. a failed renewal): the connection stays on the old certs.
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
