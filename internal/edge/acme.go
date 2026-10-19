package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

const acmeTLS1Protocol = "acme-tls/1"

func (e *Edge) serveACMEChallenge(ctx context.Context, conn net.Conn, info ClientHelloInfo, ip string) {
	domain := strings.ToLower(info.SNI)
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			e.cfg.Logger.Debug("acme tls-alpn-01 challenge close failed", "domain", domain, "ip", ip, "err", err)
		}
	}()
	cert, ok, err := e.chal.TLSALPNCertificate(ctx, domain)
	if err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge lookup failed", "domain", domain, "ip", ip, "err", err)
	}
	if err != nil || !ok {
		e.rec.Reject("no-route", info.SNI, ip)
		return
	}
	tc := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert}, NextProtos: []string{acmeTLS1Protocol}, MinVersion: tls.VersionTLS12,
	})
	if err := tc.SetDeadline(time.Now().Add(e.cfg.HandshakeTimeout)); err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge deadline failed", "domain", domain, "ip", ip, "err", err)
		return
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge handshake failed", "domain", domain, "ip", ip, "err", err)
		return
	}
	e.cfg.Logger.Debug("acme tls-alpn-01 challenge served", "domain", domain, "ip", ip)
}
