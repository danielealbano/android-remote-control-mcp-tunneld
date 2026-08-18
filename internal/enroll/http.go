package enroll

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

// BanFunc reports whether a peer IP is banned (a closure over the ban engine, so enroll stays
// decoupled from internal/ban).
type BanFunc func(netip.Addr) bool

// nonceResponse is the GET /enroll/nonce reply.
type nonceResponse struct {
	Nonce string `json:"nonce"` // hex
}

// enrollRequestBody is the POST /enroll body (Phase 1: identity only — NO TLS CSR).
type enrollRequestBody struct {
	Nonce          string `json:"nonce"`             // hex
	AttestChainPEM string `json:"attestation_chain"` // PEM bundle
	IdentityCSR    string `json:"identity_csr"`      // PEM
}

// enrollResponse returns the assigned name, the bootstrap identity cert, and a fresh single-use
// issue_nonce the phone echoes in the fresh attestation of its follow-up POST /issue (Phase 2).
type enrollResponse struct {
	Name         string `json:"name"`
	IdentityCert string `json:"identity_cert"` // PEM
	IssueNonce   string `json:"issue_nonce"`   // hex
}

type errorResponse struct {
	Reason     string `json:"reason"`
	Retryable  bool   `json:"retryable"`
	RetryAfter int64  `json:"retry_after_seconds,omitempty"`
}

// Handler is the server-TLS enroll HTTP handler (mounted on --enroll-host). Its tls.Config presents the
// publicly-trusted --enroll-host server cert supplied by server.Run; it is server-TLS only (the phone
// has no identity yet). A ban check on the peer IP is FIRST; the nonce route carries the per-IP enroll
// rate limit.
type Handler struct {
	svc     *Service
	ban     BanFunc
	rec     observ.Recorder
	maxBody int64
}

// NewHandler builds the HTTP handler. maxBody bounds the enroll POST body.
func NewHandler(svc *Service, ban BanFunc, rec observ.Recorder, maxBody int64) *Handler {
	return &Handler{svc: svc, ban: ban, rec: rec, maxBody: maxBody}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := peerIP(r)
	// Ban check FIRST.
	if addr, err := netip.ParseAddr(ip); err == nil && h.ban != nil && h.ban(addr) {
		h.rec.Reject("ban", "", ip)
		http.Error(w, "banned", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/enroll/nonce":
		h.handleNonce(w, r, ip)
	case r.Method == http.MethodPost && r.URL.Path == "/enroll":
		h.handleEnroll(w, r, ip)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleNonce(w http.ResponseWriter, r *http.Request, ip string) {
	// The nonce route carries the same per-IP enroll limit (an unauthenticated surface must not mint
	// unbounded Valkey nonce keys).
	if e := h.svc.enrollLimit(r.Context(), ip); e != nil {
		writeErr(w, e, http.StatusTooManyRequests)
		return
	}
	nonce, err := h.svc.Nonce(r.Context())
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nonceResponse{Nonce: hex.EncodeToString(nonce)})
}

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request, ip string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req enrollRequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	nonce, err := decodeHex(req.Nonce)
	if err != nil {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	chain, err := parsePEMChain([]byte(req.AttestChainPEM))
	if err != nil {
		http.Error(w, "bad attestation chain", http.StatusBadRequest)
		return
	}
	idCSR, err := parseCSR([]byte(req.IdentityCSR))
	if err != nil {
		http.Error(w, "bad identity csr", http.StatusBadRequest)
		return
	}

	// READ-ONLY per-IP limit pre-gate BEFORE any side effect: an over-limit caller must not be able to
	// mint Valkey nonce keys by flooding POST /enroll (the unauthenticated surface must not mint
	// unbounded keys). Enroll below still runs the authoritative consuming check.
	if e := h.svc.enrollLimitCheck(r.Context(), ip); e != nil {
		h.rec.EnrollmentResult(e.Reason)
		writeErr(w, e, statusForError(e))
		return
	}

	// Mint the single-use nonce for the follow-up mTLS POST /issue (Phase 2) BEFORE enrolling: a mint
	// failure must fail the request before any name is claimed (an unused nonce simply expires by TTL,
	// while a name claimed without a deliverable response would be orphaned).
	issueNonce, nerr := h.svc.Nonce(r.Context())
	if nerr != nil {
		h.rec.EnrollmentResult("internal")
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	res, ee := h.svc.Enroll(r.Context(), ip, Request{
		Nonce:          nonce,
		AttestChainPEM: []byte(req.AttestChainPEM),
		AttestChain:    chain,
		IdentityCSR:    idCSR,
	})
	if ee != nil {
		h.rec.EnrollmentResult(ee.Reason)
		writeErr(w, ee, statusForError(ee))
		return
	}

	h.rec.EnrollmentResult("ok")
	writeJSON(w, http.StatusOK, enrollResponse{
		Name:         res.Name,
		IdentityCert: string(res.IdentityCert),
		IssueNonce:   hex.EncodeToString(issueNonce),
	})
}

// statusForError maps an enrollment/issuance Error to its HTTP status.
func statusForError(e *Error) int {
	switch {
	case e.Reason == "unauthorized":
		return http.StatusUnauthorized
	case e.Retryable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, e *Error, status int) {
	resp := errorResponse{Reason: e.Reason, Retryable: e.Retryable}
	if e.RetryAfter > 0 {
		resp.RetryAfter = int64(e.RetryAfter.Seconds())
	}
	writeJSON(w, status, resp)
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func parsePEMChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	der := pemBytes
	if block != nil {
		der = block.Bytes
	}
	return x509.ParseCertificateRequest(der)
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
