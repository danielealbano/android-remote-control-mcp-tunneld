package edge

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

const acmeTLS1Protocol = "acme-tls/1"

func (e *Edge) serveACMEChallenge(ctx context.Context, conn net.Conn, info ClientHelloInfo, ip string) {
	defer func() { _ = conn.Close() }()
	domain := strings.ToLower(info.SNI)
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
	_ = tc.SetDeadline(time.Now().Add(e.cfg.HandshakeTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge handshake failed", "domain", domain, "ip", ip, "err", err)
		return
	}
	e.cfg.Logger.Debug("acme tls-alpn-01 challenge served", "domain", domain, "ip", ip)
}
