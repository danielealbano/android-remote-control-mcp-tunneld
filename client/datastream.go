package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

const defaultDialBackTimeout = 10 * time.Second

func WithDialBackTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("client: dial-back timeout must be positive")
		}
		c.dialBackTimeout = d
		return nil
	}
}

func (c *Client) handleOpen(ctx context.Context, payload []byte) {
	var op wire.OpenPayload
	if err := json.Unmarshal(payload, &op); err != nil {
		c.logger.Warn("malformed OPEN payload from the server (ignored)", "err", err)
		return
	}
	if op.Token == "" || op.Addr == "" || (op.UseMTLS && !op.UseHTTPS) {
		c.logger.Warn("invalid OPEN from the server (ignored)", "addr", op.Addr, "use_https", op.UseHTTPS, "use_mtls", op.UseMTLS)
		return
	}
	conn, err := c.dialBack(ctx, op)
	if err != nil {
		c.logger.Debug("dial-back failed", "addr", op.Addr, "err", err)
		return
	}
	stop := context.AfterFunc(ctx, func() { c.closeLogged("dial-back connection", conn) })
	c.backend(conn)
	stop()
	c.closeLogged("dial-back connection", conn)
}

func (c *Client) dialBack(ctx context.Context, op wire.OpenPayload) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.dialBackTimeout)
	defer cancel()
	nd := &net.Dialer{KeepAlive: -1}
	var conn net.Conn
	var err error
	if op.UseHTTPS {
		cfg := &tls.Config{ServerName: c.controlHost, RootCAs: c.caPool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		if op.UseMTLS {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return c.currentCert(), nil }
		}
		conn, err = (&tls.Dialer{NetDialer: nd, Config: cfg}).DialContext(dctx, "tcp", op.Addr)
	} else {
		conn, err = nd.DialContext(dctx, "tcp", op.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial-back to %s: %w", op.Addr, err)
	}
	br, err := upgradeDialBack(dctx, conn, c.controlHost, op.Token)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("dial-back upgrade at %s: %w", op.Addr, err), conn.Close())
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

func upgradeDialBack(ctx context.Context, conn net.Conn, host, token string) (*bufio.Reader, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("set the upgrade deadline: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+wire.DialBackPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build the upgrade request: %w", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", wire.DialUpgrade)
	req.Header.Set(wire.DialTokenHeader, token)
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write the upgrade request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read the upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, errors.Join(fmt.Errorf("client: dial-back refused: %s", resp.Status), resp.Body.Close())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear the upgrade deadline: %w", err)
	}
	return br, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
