package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Controller executes a mesh control op. Implemented in internal/server (mesh MUST
// NOT import phoneconn/enroll). Renew enqueues a RENEW_NUDGE; Terminate closes the tunnel's live phone
// connection and evicts this node's in-flight public splices. Each returns whether it applied.
type Controller interface {
	TunnelController
	ConnController
}

type TunnelController interface {
	Renew(ctx context.Context, tunnel string) (bool, error)
	Terminate(ctx context.Context, tunnel string) (bool, error)
}

type ConnController interface {
	Open(ctx context.Context, tunnel, connID string, open wire.OpenPayload) (bool, error)
	Evict(ctx context.Context, tunnel, connID, reason string) (bool, error)
}

// ControlRequest / ControlResponse are the /api/v1/mesh/control JSON envelope (replica↔replica only).
type ControlRequest struct {
	Op     string            `json:"op"`
	Tunnel string            `json:"tunnel"` // the tunnel name to act on
	ConnID string            `json:"conn_id,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Open   *wire.OpenPayload `json:"open,omitempty"`
}

type ControlResponse struct {
	Applied bool `json:"applied"` // renew: a nudge was enqueued; terminate: a live phone conn was closed
}

// Handler is the mesh listener handler. It requires a mesh-role peer cert — the mTLS config verifies the
// chain to the internal CA (RequireAndVerifyClientCert) and this handler enforces the mesh-role marker
// (an identity-role cert is rejected). (The peer's node-id SAN is NOT checked against the node registry:
// chain-to-CA + mesh-role + short-lived mesh certs are the mesh's authentication.)
type Handler struct {
	control Controller
	logger  *slog.Logger
}

type HandlerOption func(*Handler) error

func WithHandlerLogger(l *slog.Logger) HandlerOption {
	return func(h *Handler) error {
		if l == nil {
			return errors.New("mesh: nil logger")
		}
		h.logger = l
		return nil
	}
}

// NewHandler builds the mesh handler.
func NewHandler(control Controller, opts ...HandlerOption) (*Handler, error) {
	h := &Handler{control: control, logger: slog.Default()}
	for _, o := range opts {
		if err := o(h); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Mesh-role peer cert required (identity-role rejected).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !ca.HasMeshRole(r.TLS.PeerCertificates[0]) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/api/v1/mesh/control" {
		http.NotFound(w, r)
		return
	}
	h.serveControl(w, r)
}

// serveControl handles the mesh control RPC (mesh-role mTLS already enforced by ServeHTTP): a JSON
// {op, tunnel} → {applied} request/response. Unknown op / missing tunnel → 400; op failure → 502.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ControlRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		h.logger.Warn("mesh control request malformed", "err", err)
		http.Error(w, "bad control request", http.StatusBadRequest)
		return
	}
	if req.Op != "renew" && req.Op != "terminate" && req.Op != "open" && req.Op != "evict" {
		http.Error(w, "unknown op", http.StatusBadRequest)
		return
	}
	if req.Tunnel == "" {
		http.Error(w, "missing tunnel", http.StatusBadRequest)
		return
	}
	if (req.Op == "open" || req.Op == "evict") && req.ConnID == "" {
		http.Error(w, "missing conn_id", http.StatusBadRequest)
		return
	}
	if req.Op == "open" && (req.Open == nil || req.Open.Token == "" || req.Open.Addr == "") {
		http.Error(w, "bad open request", http.StatusBadRequest)
		return
	}
	var applied bool
	var err error
	switch req.Op {
	case "renew":
		applied, err = h.control.Renew(r.Context(), req.Tunnel)
	case "terminate":
		applied, err = h.control.Terminate(r.Context(), req.Tunnel)
	case "open":
		applied, err = h.control.Open(r.Context(), req.Tunnel, req.ConnID, *req.Open)
	case "evict":
		applied, err = h.control.Evict(r.Context(), req.Tunnel, req.ConnID, req.Reason)
	}
	if err != nil {
		h.logger.Warn("mesh control op failed", "op", req.Op, "tunnel", req.Tunnel, "err", err)
		http.Error(w, req.Op+" failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ControlResponse{Applied: applied}); err != nil {
		h.logger.Debug("mesh control response write failed", "op", req.Op, "tunnel", req.Tunnel, "err", err)
	}
}
