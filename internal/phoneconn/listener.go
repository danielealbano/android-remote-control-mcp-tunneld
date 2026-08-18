package phoneconn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// ErrNoConn is returned when no live phone connection exists for a tunnel name.
var ErrNoConn = errors.New("phoneconn: no live connection")

// NameValidator validates a CN as a well-formed, non-reserved tunnel name.
type NameValidator func(name string) bool

// BanTunnel reports whether (name, fingerprint) is banned.
type BanTunnel func(name, fingerprint string) bool

// Handler is the phone control-plane HTTP handler (mounted behind the reserved --control-host TLS
// terminator by server.Run). It serves the long-lived /control stream and the dial-back /data streams,
// both authenticated by the internal-CA identity client cert (mTLS). The name is DERIVED from the cert
// CN (the phone dials the single shared --control-host).
type Handler struct {
	mgr           *Manager
	validName     NameValidator
	banIP         BanIP
	banTunnel     BanTunnel
	reject        RejectFunc
	pingInterval  time.Duration
	streamPending int
	onIssue       IssueFunc
	issueBody     int64

	sem chan struct{} // bounds concurrent pre-bind handshakes (--limit-stream-pending)
}

// BanIP reports whether the phone's peer IP is banned.
type BanIP func(addr netip.Addr) bool

// IssueRequest is the POST /issue body: a fresh attestation over the enroll/nudge nonce plus rotated
// identity and TLS CSRs. It is the SINGLE certificate-generation request for BOTH the initial public
// cert (right after enrollment) and every renewal — it regenerates the identity + public certs together.
type IssueRequest struct {
	Nonce               string `json:"nonce"`             // hex
	AttestationChainPEM string `json:"attestation_chain"` // PEM bundle
	IdentityCSR         string `json:"identity_csr"`      // PEM
	TLSCSR              string `json:"tls_csr"`           // PEM (SAN = <name>.<tunnel-domain>)
}

// IssueResponse returns the regenerated identity + public certs.
type IssueResponse struct {
	IdentityCert string `json:"identity_cert"`
	PublicCert   string `json:"public_cert"`
	CA           string `json:"ca"`
}

// IssueError is a structured issuance failure (mapped to an HTTP status by serveIssue).
type IssueError struct {
	Reason       string
	Retryable    bool
	Unauthorized bool
}

func (e *IssueError) Error() string { return "phoneconn: " + e.Reason }

// IssueFunc regenerates the identity + public certs for an mTLS-authenticated tunnel (name from the
// client-cert CN). fp is the identity-cert fingerprint; ip is the phone's peer address for evidence.
type IssueFunc func(ctx context.Context, name, fp, ip string, req IssueRequest) (IssueResponse, *IssueError)

// HandlerConfig wires the Handler.
type HandlerConfig struct {
	Manager       *Manager
	ValidName     NameValidator
	BanIP         BanIP
	BanTunnel     BanTunnel
	Reject        RejectFunc // rejection metric writer (the phone control plane is a `ban` writer)
	PingInterval  time.Duration
	StreamPending int
	OnIssue       IssueFunc
	IssueBody     int64 // max POST /issue body (bytes); defaults to 256 KiB
}

// RejectFunc records one rejection (reason ∈ observ.RejectReasons — satisfied by PromRecorder.Reject).
type RejectFunc func(reason, tunnelName, clientIP string)

// NewHandler builds the phone control handler.
func NewHandler(cfg HandlerConfig) *Handler {
	if cfg.StreamPending < 1 {
		cfg.StreamPending = 64
	}
	if cfg.IssueBody < 1 {
		cfg.IssueBody = 256 * 1024
	}
	reject := cfg.Reject
	if reject == nil {
		reject = func(string, string, string) {}
	}
	return &Handler{
		mgr: cfg.Manager, validName: cfg.ValidName, banIP: cfg.BanIP, banTunnel: cfg.BanTunnel,
		reject: reject, pingInterval: cfg.PingInterval, streamPending: cfg.StreamPending,
		onIssue: cfg.OnIssue, issueBody: cfg.IssueBody,
		sem: make(chan struct{}, cfg.StreamPending),
	}
}

// identity extracts and validates the identity-role client cert, returning the derived name + its
// fingerprint. Rejects: no cert, mesh-role marker, malformed/reserved CN.
func (h *Handler) identity(r *http.Request) (name, fingerprint string, ok bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", "", false
	}
	leaf := r.TLS.PeerCertificates[0]
	if ca.HasMeshRole(leaf) {
		return "", "", false // mesh-role cert rejected on the phone listener
	}
	cn := leaf.Subject.CommonName
	if h.validName != nil && !h.validName(cn) {
		return "", "", false
	}
	return cn, ca.Fingerprint(leaf), true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Peer-IP ban check FIRST — a newly-banned IP must not keep using an established mTLS identity.
	ip := peerIP(r)
	if h.banIP != nil {
		if addr, err := netip.ParseAddr(ip); err == nil && h.banIP(addr) {
			h.reject("ban", "", ip)
			http.Error(w, "banned", http.StatusForbidden)
			return
		}
	}
	name, fp, ok := h.identity(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.banTunnel != nil && h.banTunnel(name, fp) {
		h.reject("ban", name, ip)
		http.Error(w, "banned", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/control":
		h.serveControl(w, r, name, fp)
	case "/data":
		h.serveData(w, r, name)
	case "/issue":
		h.serveIssue(w, r, name, fp)
	default:
		http.NotFound(w, r)
	}
}

// serveIssue is the mTLS certificate-generation endpoint (initial public cert AND every renewal): it
// reads the tunnel name from the authenticated client-cert CN, hands the request to OnIssue, and returns
// the regenerated identity + public certs. POST only.
func (h *Handler) serveIssue(w http.ResponseWriter, r *http.Request, name, fp string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.onIssue == nil {
		http.Error(w, "issuance unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.issueBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req IssueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	resp, ierr := h.onIssue(r.Context(), name, fp, peerIP(r), req)
	if ierr != nil {
		status := http.StatusBadRequest
		if ierr.Retryable {
			status = http.StatusServiceUnavailable
		}
		if ierr.Unauthorized {
			status = http.StatusUnauthorized
		}
		writeJSON(w, status, map[string]any{"reason": ierr.Reason, "retryable": ierr.Retryable})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// peerIP returns the connecting phone's IP (host part of RemoteAddr).
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// livenessMissedPings is how many consecutive PING intervals may elapse without a PONG before the
// connection is torn down as dead (tolerates one lost PONG without a spurious kill).
const livenessMissedPings = 3

// serveControl runs the long-lived bidirectional control stream: it writes queued frames to the
// response body and reads incoming frames (PONG liveness) from the request body. The pre-bind
// semaphore (--limit-stream-pending) is held ONLY until the route bind completes — it bounds
// concurrent pre-bind handshakes, never the number of bound phones.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request, name, fp string) {
	select {
	case h.sem <- struct{}{}:
	default:
		http.Error(w, "too many pending", http.StatusServiceUnavailable)
		return
	}
	semHeld := true
	releaseSem := func() {
		if semHeld {
			semHeld = false
			<-h.sem
		}
	}
	defer releaseSem()
	flusher, okf := w.(http.Flusher)
	if !okf {
		http.Error(w, "no http/2", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	c := &conn{
		name: name, fingerprint: fp, connID: mustConnID(time.Now()),
		sessionStart: h.mgr.now(), meta: metaFromRequest(r),
		send: make(chan []byte, 32), cancel: cancel, pending: map[string]chan DataStream{},
	}
	c.lastPong.Store(c.sessionStart.UnixNano())
	teardown, err := h.mgr.register(ctx, c)
	if err != nil {
		http.Error(w, "bind failed", http.StatusConflict)
		return
	}
	defer teardown()
	releaseSem() // bound — the pre-bind slot frees for the next handshake

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	go h.mgr.heartbeatLoop(ctx, c)
	go h.readPump(r.Body, c)

	ping := time.NewTicker(h.pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-c.send:
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		case <-ping.C:
			// Liveness: a phone that has not PONGed for livenessMissedPings intervals is dead.
			if time.Since(time.Unix(0, c.lastPong.Load())) > time.Duration(livenessMissedPings)*h.pingInterval {
				c.close("liveness-timeout")
				return
			}
			pf, _ := wire.EncodeControl(wire.CtrlPing, nil) // nil payload cannot fail to marshal
			if _, err := w.Write(pf); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// readPump drains incoming control frames from the phone (length-framed). The phone→server direction
// carries only PONG liveness (certificate work moved to the mTLS POST /issue endpoint); a read error
// or a malformed frame tears the connection down.
func (h *Handler) readPump(body io.Reader, c *conn) {
	for {
		frame, err := readControlFrame(body)
		if err != nil {
			c.close("phone-close")
			return
		}
		typ, _, derr := wire.DecodeControl(frame)
		if derr != nil {
			c.close("protocol-error")
			return
		}
		if typ == wire.CtrlPong {
			c.lastPong.Store(time.Now().UnixNano())
		}
	}
}

// serveData delivers an arriving dial-back data stream to its waiter and blocks (keeping the HTTP
// handler open) while the bridge splices, until the stream is done. No header is written before the
// delivery succeeds, so an undeliverable stream gets a REAL 404 (the response commits on the bridge's
// first Write; only the bridge goroutine touches w after delivery).
func (h *Handler) serveData(w http.ResponseWriter, r *http.Request, name string) {
	streamID := r.Header.Get("X-Stream-Id")
	if streamID == "" {
		http.Error(w, "missing stream id", http.StatusBadRequest)
		return
	}
	flusher, okf := w.(http.Flusher)
	if !okf {
		http.Error(w, "no http/2", http.StatusBadRequest)
		return
	}
	done := make(chan struct{})
	ds := &httpDataStream{r: r.Body, w: w, flush: flusher.Flush, done: done}
	if !h.mgr.deliverStream(name, streamID, ds) {
		http.Error(w, "no such stream", http.StatusNotFound)
		return
	}
	<-done // hold the handler open while the bridge splices
}

func metaFromRequest(r *http.Request) ConnMeta {
	// The edge peeks the ClientHello and hands the ConnMeta (SNI/ALPN/version/JA4 + peer address) via
	// http.Server.ConnContext (see ConnContext); use it when present.
	if m, ok := r.Context().Value(connMetaKey{}).(ConnMeta); ok {
		if m.ALPN == "" && r.TLS != nil {
			m.ALPN = r.TLS.NegotiatedProtocol
		}
		return m
	}
	// Absent the hand-off (e.g. a direct connection in tests), derive what we can from the request.
	m := ConnMeta{}
	if r.TLS != nil {
		m.ALPN = r.TLS.NegotiatedProtocol
	}
	return m
}

// mustConnID mints a phone connID seeded by the session start (best-effort; falls back to a zero id).
func mustConnID(now time.Time) string {
	id, err := store.NewConnID(now, now)
	if err != nil {
		return "0000000000"
	}
	return id
}
