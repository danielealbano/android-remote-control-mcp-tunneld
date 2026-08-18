// Package phoneconn implements the phone-facing HTTP/2 + internal-CA-mTLS control plane: the identity-
// role listener, the long-lived control stream, owner-conditional route bind/heartbeat/unbind carrying
// the tunnel-session start, start/end connection-log events, dial-back data streams, liveness,
// renewal-with-rotation, and tunnel-name/fingerprint ban enforcement + live eviction. It replaces the
// Plan-1 internal/wsconn.
package phoneconn

import (
	"context"
	"net"
)

// ConnMeta is the ClientHello metadata the US11 SNI edge peeks and hands to the local terminators and
// bridges, so both phone and public connection-log events carry JA4/ALPN/version + the peer address.
// Defined here (not in internal/edge) so both phoneconn and edge use it without an import cycle (edge
// imports phoneconn for dial-back, never the reverse).
type ConnMeta struct {
	SNI        string
	ALPN       string
	TLSVersion string
	JA4        string
	SrcIP      string
	SrcPort    int
}

// ConnMetaCarrier is implemented by the edge's control-host connection wrapper: it exposes the peeked
// ClientHello metadata so the phone control handler can stamp JA4/ALPN/version onto its connection-log
// events. server.Run bridges it into the request via ConnContext.
type ConnMetaCarrier interface {
	ConnMeta() ConnMeta
}

type connMetaKey struct{}

// ConnContext is wired as http.Server.ConnContext on the control listener: it unwraps the accepted
// connection (through the tls.Conn) to the edge's ConnMetaCarrier and stashes the peeked ConnMeta in
// the request context, where metaFromRequest reads it.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	for c != nil {
		if mc, ok := c.(ConnMetaCarrier); ok {
			return context.WithValue(ctx, connMetaKey{}, mc.ConnMeta())
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		c = u.NetConn()
	}
	return ctx
}
