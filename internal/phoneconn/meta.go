// Package phoneconn implements the phone-facing HTTP/2 + internal-CA-mTLS control plane: the identity-
// role listener, the long-lived control stream, owner-conditional route bind/heartbeat/unbind carrying
// the tunnel-session start, start/end connection-log events, dial-back data streams, liveness,
// renewal-with-rotation, and tunnel-name/fingerprint ban enforcement + live eviction. It replaces the
// Plan-1 internal/wsconn.
package phoneconn

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
