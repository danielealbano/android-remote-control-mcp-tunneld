package enroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func newTestHandler(t *testing.T, svc *Service, ban BanFunc) *Handler {
	t.Helper()
	return NewHandler(svc, ban, observ.Nop{}, 64*1024)
}

func csrPEM(t *testing.T, csr *x509.CertificateRequest) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}))
}

// TestHandlerBanFirst: the plan's ban-first requirement on the enroll surface.
func TestHandlerBanFirst(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	banned := netip.MustParseAddr("203.0.113.13")
	h := newTestHandler(t, svc, func(a netip.Addr) bool { return a == banned })

	req := httptest.NewRequest("GET", "/enroll/nonce", nil)
	req.RemoteAddr = "203.0.113.13:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("banned IP must get 403 before anything else, got %d", rr.Code)
	}
	_ = idCSR
}

// TestHandlerDecodeErrors: the plan's "http decode + structured error" row — malformed body/nonce/chain
// each answer 400 without touching the service.
func TestHandlerDecodeErrors(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	tests := []struct {
		name string
		body string
	}{
		{name: "bad json", body: "{not-json"},
		{name: "bad nonce hex", body: `{"nonce":"zz","attestation_chain":"","identity_csr":""}`},
		{name: "bad identity csr", body: `{"nonce":"aabb","attestation_chain":"","identity_csr":"not-pem"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/enroll", bytes.NewReader([]byte(tc.body)))
			req.RemoteAddr = "203.0.113.14:5000"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != 400 {
				t.Fatalf("want 400, got %d", rr.Code)
			}
		})
	}
	if st.NameCount() != 0 {
		t.Fatal("decode failures must not reach the claim path")
	}
}

// TestHandlerStructuredError: a service rejection surfaces as the structured {reason, retryable} body
// with the mapped status.
func TestHandlerStructuredError(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st, EnrollMinute: 1, EnrollHour: 100,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	body := func() []byte {
		b, _ := json.Marshal(enrollRequestBody{Nonce: "aabb", IdentityCSR: csrPEM(t, idCSR)})
		return b
	}
	// Exhaust the per-IP minute limit, then expect the structured enroll_rate error with 503.
	if e := svc.enrollLimit(context.Background(), "203.0.113.15"); e != nil {
		t.Fatalf("first limit draw must pass: %v", e)
	}
	req := httptest.NewRequest("POST", "/enroll", bytes.NewReader(body()))
	req.RemoteAddr = "203.0.113.15:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatalf("retryable rejection must map to 503, got %d", rr.Code)
	}
	var er errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil || er.Reason != "enroll_rate" || !er.Retryable {
		t.Fatalf("want structured enroll_rate retryable error, got %s", rr.Body.String())
	}
}

// TestHandlerNonceRouteRateLimited: the plan's "nonce route rate-limited" row — an over-limit IP is
// refused on GET /enroll/nonce and no Valkey nonce key is created.
func TestHandlerNonceRouteRateLimited(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, mr := newService(t, Config{CA: testCA(t), Names: st, Evidence: st, EnrollMinute: 1, EnrollHour: 100,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/enroll/nonce", nil)
		req.RemoteAddr = "203.0.113.16:5000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := get(); rr.Code != 200 {
		t.Fatalf("first nonce mint must pass, got %d", rr.Code)
	}
	keysBefore := len(mr.Keys())
	if rr := get(); rr.Code != 429 {
		t.Fatalf("over-limit nonce mint must be refused with 429, got %d", rr.Code)
	}
	if len(mr.Keys()) > keysBefore {
		t.Fatal("a refused nonce mint must not create a Valkey nonce key")
	}
}

// TestHandlerNonceMintedBeforeClaim: a failing issue-nonce mint answers 500 BEFORE any name is
// claimed (no orphaned registry record).
func TestHandlerNonceMintedBeforeClaim(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, mr := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	nonce := mintNonce(t, svc)
	b, _ := json.Marshal(enrollRequestBody{Nonce: hexEncode(nonce), IdentityCSR: csrPEM(t, idCSR)})
	mr.Close() // Valkey down: the issue-nonce mint fails (and so would everything after)
	req := httptest.NewRequest("POST", "/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.17:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 500 {
		t.Fatalf("a failing issue-nonce mint must answer 500, got %d", rr.Code)
	}
	if st.NameCount() != 0 {
		t.Fatal("no name may be claimed when the response cannot carry an issue nonce")
	}
}

// TestHandlerHappyPath: a full decode→enroll round trip returns name + identity cert + issue nonce.
func TestHandlerHappyPath(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	nonce := mintNonce(t, svc)
	b, _ := json.Marshal(enrollRequestBody{Nonce: hexEncode(nonce), IdentityCSR: csrPEM(t, idCSR)})
	req := httptest.NewRequest("POST", "/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.18:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("enroll failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil ||
		resp.Name == "" || resp.IdentityCert == "" || resp.IssueNonce == "" {
		t.Fatalf("want name + identity cert + issue nonce, got %s", rr.Body.String())
	}
}

func hexEncode(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdig[c>>4], hexdig[c&0xf])
	}
	return string(out)
}
