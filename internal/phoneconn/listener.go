package phoneconn

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
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
	banTunnel     BanTunnel
	pingInterval  time.Duration
	streamPending int
	onRenew       RenewFunc
	challenge     ChallengeFunc

	sem chan struct{} // bounds concurrent pre-bind handshakes (--limit-stream-pending)
}

// RenewFunc handles a renewal submission, returning the pushed certs or an error. nonceHex is the
// server-minted renewal challenge (a real single-use enroll nonce) the phone echoed in its fresh
// attestation; ip is the phone's peer address (from the peeked ConnMeta) for rejection evidence.
type RenewFunc func(ctx context.Context, name, nonceHex, ip string, sub wire.RenewSubmitPayload) (wire.CertPushPayload, error)

// ChallengeFunc mints a fresh single-use renewal challenge nonce (hex), stored server-side (Valkey)
// exactly like an initial-enrollment nonce so the renewal submission validates through the same path.
type ChallengeFunc func(ctx context.Context) (nonceHex string, err error)

// HandlerConfig wires the Handler.
type HandlerConfig struct {
	Manager       *Manager
	ValidName     NameValidator
	BanTunnel     BanTunnel
	PingInterval  time.Duration
	StreamPending int
	OnRenew       RenewFunc
	Challenge     ChallengeFunc
}

// NewHandler builds the phone control handler.
func NewHandler(cfg HandlerConfig) *Handler {
	if cfg.StreamPending < 1 {
		cfg.StreamPending = 64
	}
	return &Handler{
		mgr: cfg.Manager, validName: cfg.ValidName, banTunnel: cfg.BanTunnel,
		pingInterval: cfg.PingInterval, streamPending: cfg.StreamPending, onRenew: cfg.OnRenew,
		challenge: cfg.Challenge,
		sem:       make(chan struct{}, cfg.StreamPending),
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
	name, fp, ok := h.identity(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.banTunnel != nil && h.banTunnel(name, fp) {
		http.Error(w, "banned", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/control":
		h.serveControl(w, r, name, fp)
	case "/data":
		h.serveData(w, r, name)
	default:
		http.NotFound(w, r)
	}
}

// serveControl runs the long-lived bidirectional control stream: it writes queued frames to the
// response body and reads incoming frames (PONG, RENEW_*) from the request body.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request, name, fp string) {
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		http.Error(w, "too many pending", http.StatusServiceUnavailable)
		return
	}
	flusher, okf := w.(http.Flusher)
	if !okf {
		http.Error(w, "no http/2", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	c := &conn{
		name: name, fingerprint: fp, connID: mustConnID(h.mgr, time.Now()),
		sessionStart: h.mgr.now(), meta: metaFromRequest(r),
		send: make(chan []byte, 32), cancel: cancel, pending: map[string]chan DataStream{},
	}
	teardown, err := h.mgr.register(ctx, c)
	if err != nil {
		http.Error(w, "bind failed", http.StatusConflict)
		return
	}
	defer teardown()

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	go h.mgr.heartbeatLoop(ctx, c)
	go h.readPump(ctx, r.Body, c)

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
			pf, _ := wire.EncodeControl(wire.CtrlPing, nil)
			if _, err := w.Write(pf); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// readPump decodes incoming control frames from the phone (length-framed) and dispatches them.
func (h *Handler) readPump(ctx context.Context, body io.Reader, c *conn) {
	for {
		frame, err := readControlFrame(body)
		if err != nil {
			c.close("phone-close")
			return
		}
		ct, payload, derr := wire.DecodeControl(frame)
		if derr != nil {
			continue
		}
		switch ct {
		case wire.CtrlPong:
			// liveness ok
		case wire.CtrlRenewRequest:
			h.sendRenewChallenge(ctx, c)
		case wire.CtrlRenewSubmit:
			h.handleRenewSubmit(ctx, c, payload)
		}
	}
}

// serveData delivers an arriving dial-back data stream to its waiter and blocks (keeping the HTTP
// handler open) while the bridge splices, until the stream is done.
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
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
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

// mustConnID mints a phone connID seeded by the session start (best-effort; falls back to now).
func mustConnID(m *Manager, now time.Time) string {
	id, err := store.NewConnID(now, now)
	if err != nil {
		return "0000000000"
	}
	return id
}

var _ = x509.Certificate{}
