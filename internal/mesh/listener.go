package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
)

// ErrDuplicateStream reports a dial-back stream id already pending on the owner's phone connection
// (the entry node re-mints the id and retries once). It crosses the mesh boundary as a mesh-owned
// sentinel because mesh MUST NOT import phoneconn.
var ErrDuplicateStream = errors.New("mesh: duplicate stream id")

// Bridge opens the local phone dial-back stream (open phase — BEFORE the mesh response commits, so
// an open failure can still pick the HTTP status) and then splices it with the mesh client stream. It
// is implemented by the owner node's edge bridge wrapping phoneconn.OpenStream + the paced copy.
type Bridge interface {
	OpenMesh(ctx context.Context, tunnel, streamID string) (io.ReadWriteCloser, error)
	SpliceMesh(ds, client io.ReadWriteCloser)
}

// OwnerCheck reports whether this node holds the live phone connection for tunnel with connID.
type OwnerCheck func(tunnel, connID string) bool

// Controller executes a mesh control op on THIS (owner) node. Implemented in internal/server (mesh MUST
// NOT import phoneconn/enroll). Renew mints a fresh renewal nonce and enqueues a RENEW_NUDGE to the
// named tunnel's live phone connection, returning whether it was enqueued.
type Controller interface {
	Renew(ctx context.Context, tunnel string) (bool, error)
}

// ControlRequest / ControlResponse are the /mesh/control JSON envelope (replica↔replica only).
type ControlRequest struct {
	Op     string `json:"op"`     // "renew"
	Tunnel string `json:"tunnel"` // the tunnel name whose phone to nudge
}

type ControlResponse struct {
	Nudged bool `json:"nudged"`
}

// Handler is the mesh listener handler. It requires a mesh-role peer cert — the mTLS config verifies the
// chain to the internal CA (RequireAndVerifyClientCert) and this handler enforces the mesh-role marker
// (an identity-role cert is rejected). It reads the stream identity from the X-Tunnel / X-Conn-Id /
// X-Stream-Id request headers (docs/PROTOCOL.md §5), verifies the connID against the
// live phone connection, and bridges to the phone. (The peer's node-id SAN is NOT checked against the
// node registry: chain-to-CA + mesh-role + the connID delivery check + short-lived mesh certs are the
// mesh's authentication.)
type Handler struct {
	owns    OwnerCheck
	bridge  Bridge
	control Controller
}

// NewHandler builds the mesh handler.
func NewHandler(owns OwnerCheck, bridge Bridge, control Controller) *Handler {
	return &Handler{owns: owns, bridge: bridge, control: control}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Mesh-role peer cert required (identity-role rejected). FIRST so it guards BOTH paths below.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !ca.HasMeshRole(r.TLS.PeerCertificates[0]) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/mesh/data":
		h.serveData(w, r)
	case "/mesh/control":
		h.serveControl(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveControl handles the mesh control RPC (mesh-role mTLS already enforced by ServeHTTP): a JSON
// {op, tunnel} → {nudged} request/response. The first op is "renew", which forces this owner node to
// nudge the named tunnel's live phone connection.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ControlRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad control request", http.StatusBadRequest)
		return
	}
	switch req.Op {
	case "renew":
		if req.Tunnel == "" {
			http.Error(w, "missing tunnel", http.StatusBadRequest)
			return
		}
		nudged, err := h.control.Renew(r.Context(), req.Tunnel)
		if err != nil {
			http.Error(w, "renew failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ControlResponse{Nudged: nudged})
	default:
		http.Error(w, "unknown op", http.StatusBadRequest)
	}
}

// serveData is the opaque bidirectional splice (docs/PROTOCOL.md §5): the request/response bodies ARE the
// client stream from the owner's perspective. Mesh-role mTLS is already enforced by ServeHTTP.
func (h *Handler) serveData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // docs/PROTOCOL.md §5: a mesh stream is a POST /mesh/data
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tunnel := r.Header.Get("X-Tunnel")
	connID := r.Header.Get("X-Conn-Id")
	streamID := r.Header.Get("X-Stream-Id")
	if tunnel == "" || connID == "" || streamID == "" {
		http.Error(w, "bad mesh headers", http.StatusBadRequest)
		return
	}
	// connID owner check against the live phone connection.
	if h.owns == nil || !h.owns(tunnel, connID) {
		http.Error(w, "not owner", http.StatusConflict)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no http/2", http.StatusBadRequest)
		return
	}
	// Open phase BEFORE committing the response status, so a dial-back failure can still pick the code:
	// a duplicate pending stream id is 422 (distinct from the 409 not-owner), any other failure is 502.
	ds, err := h.bridge.OpenMesh(r.Context(), tunnel, streamID)
	if err != nil {
		if errors.Is(err, ErrDuplicateStream) {
			http.Error(w, "duplicate stream", http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "dial-back failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// The mesh request/response bodies ARE the client stream from the owner's perspective:
	// Read = request body (client→phone), Write = response body (phone→client).
	rc := http.NewResponseController(w)
	cs := &ownerStream{r: r.Body, w: w, flush: flusher.Flush, done: make(chan struct{}),
		unblock: func() { _ = rc.SetWriteDeadline(time.Now()) }}
	h.bridge.SpliceMesh(ds, cs)
	<-cs.done
}

// ownerStream is the owner-side view of a mesh stream: Read pulls client→phone bytes from the /mesh/data
// request body; Write pushes phone→client bytes to the /mesh/data response body. Write and Close share a mutex
// + closed flag so that once Close releases the handler, NO further Write touches the HTTP/2 response
// writer (which the http2 library finalizes as the handler returns).
type ownerStream struct {
	r       io.Reader
	w       io.Writer
	flush   func()
	done    chan struct{}
	unblock func() // resets the HTTP/2 stream so a flow-control-blocked Write fails and releases o.mu
	once    sync.Once

	mu     sync.Mutex
	closed bool
}

func (o *ownerStream) Read(p []byte) (int, error) { return o.r.Read(p) }
func (o *ownerStream) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := o.w.Write(p)
	if o.flush != nil {
		o.flush()
	}
	return n, err
}
func (o *ownerStream) Close() error {
	o.once.Do(func() {
		// Reset the HTTP/2 stream FIRST so an in-flight flow-control-blocked Write fails and releases
		// o.mu — otherwise Close would deadlock on the mutex and pin the mesh splice.
		if o.unblock != nil {
			o.unblock()
		}
		o.mu.Lock()
		o.closed = true
		o.mu.Unlock()
		close(o.done)
	})
	return nil
}
