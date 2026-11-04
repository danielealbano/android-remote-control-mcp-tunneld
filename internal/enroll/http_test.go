package enroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type fakeLifecycle struct{ stopping, draining bool }

func (f fakeLifecycle) Stopping() bool { return f.stopping }
func (f fakeLifecycle) Draining() bool { return f.draining }

func newTestHandler(t *testing.T, svc *Service, ban BanFunc) *Handler {
	t.Helper()
	return newTestHandlerLife(t, svc, ban, fakeLifecycle{})
}

func newTestHandlerLife(t *testing.T, svc *Service, ban BanFunc, life Lifecycle) *Handler {
	t.Helper()
	rec := &tunneltest.Recorder{}
	t.Cleanup(func() {
		known := map[string]bool{}
		for _, r := range observ.EnrollResults {
			known[r] = true
		}
		for _, c := range rec.Calls {
			if c.Kind == "enrollmentresult" && !known[c.Result] {
				t.Errorf("enrollment result %q is not in observ.EnrollResults", c.Result)
			}
		}
	})
	return NewHandler(svc, ban, rec, 64*1024, life)
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

	req := httptest.NewRequest("GET", "/api/v1/enroll/nonce", nil)
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
		name       string
		body       string
		wantReason string
	}{
		{name: "bad json", body: "{not-json", wantReason: "bad_json"},
		{name: "bad nonce hex", body: `{"nonce":"zz","attestation_chain":"","identity_csr":""}`, wantReason: "bad_nonce"},
		{name: "bad identity csr", body: `{"nonce":"aabb","attestation_chain":"","identity_csr":"not-pem"}`, wantReason: "bad_identity_csr"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader([]byte(tc.body)))
			req.RemoteAddr = "203.0.113.14:5000"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != 400 {
				t.Fatalf("want 400, got %d", rr.Code)
			}
			// Decode failures follow the SAME documented JSON error schema as service errors.
			var er errorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil || er.Reason != tc.wantReason {
				t.Fatalf("want structured %q error, got %s (decode error: %v)", tc.wantReason, rr.Body.String(), err)
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
		b, err := json.Marshal(enrollRequestBody{Nonce: "aabb", IdentityCSR: csrPEM(t, idCSR)})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// Exhaust the per-IP minute limit, then expect the structured enroll_rate error with 503.
	if e := svc.enrollLimit(context.Background(), "203.0.113.15"); e != nil {
		t.Fatalf("first limit draw must pass: %v", e)
	}
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body()))
	req.RemoteAddr = "203.0.113.15:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatalf("retryable rejection must map to 503, got %d", rr.Code)
	}
	var er errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil || er.Reason != "enroll_rate" || !er.Retryable {
		t.Fatalf("want structured enroll_rate retryable error, got %s (decode error: %v)", rr.Body.String(), err)
	}
}

// TestHandlerNonceRouteRateLimited: the plan's "nonce route rate-limited" row — an over-limit IP is
// refused on GET /api/v1/enroll/nonce and no Valkey nonce key is created.
func TestHandlerNonceRouteRateLimited(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, mr := newService(t, Config{CA: testCA(t), Names: st, Evidence: st, EnrollMinute: 1, EnrollHour: 100,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/enroll/nonce", nil)
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

// TestHandleNonce_BadSourceIPIs400 verifies the GET /api/v1/enroll/nonce route answers 400 bad_source_ip for an
// unparseable peer IP (not 429): the ban gate fails closed.
func TestHandleNonce_BadSourceIPIs400(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	req := httptest.NewRequest("GET", "/api/v1/enroll/nonce", nil)
	req.RemoteAddr = "not-an-ip" // no host:port → unparseable
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("an unparseable peer IP must answer 400, got %d", rr.Code)
	}
	var er errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil {
		t.Fatal(err)
	}
	if er.Reason != "bad_source_ip" {
		t.Fatalf("reason = %q, want bad_source_ip", er.Reason)
	}
}

// TestServeHTTP_UnparseableIPRejected verifies the POST /api/v1/enroll route also refuses an unparseable peer IP
// BEFORE dispatch (fail closed), without touching the service.
func TestServeHTTP_UnparseableIPRejected(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	b, err := json.Marshal(enrollRequestBody{Nonce: hexEncode(mintNonce(t, svc)), IdentityCSR: csrPEM(t, idCSR)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
	req.RemoteAddr = "garbage-addr"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("an unparseable peer IP must be refused 400, got %d", rr.Code)
	}
	if st.NameCount() != 0 {
		t.Fatal("no name must be claimed when the peer IP is refused")
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
	b, err := json.Marshal(enrollRequestBody{Nonce: hexEncode(nonce), IdentityCSR: csrPEM(t, idCSR)})
	if err != nil {
		t.Fatal(err)
	}
	mr.Close() // Valkey down: the issue-nonce mint fails (and so would everything after)
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.17:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatalf("a failing issue-nonce mint must answer 503 (retryable), got %d", rr.Code)
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
	b, err := json.Marshal(enrollRequestBody{Nonce: hexEncode(nonce), IdentityCSR: csrPEM(t, idCSR)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.18:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("enroll failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil ||
		resp.Name == "" || resp.IdentityCert == "" || resp.IssueNonce == "" {
		t.Fatalf("want name + identity cert + issue nonce, got %s (decode error: %v)", rr.Body.String(), err)
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

// TestHandlerOverLimitDoesNotMintNonce: an over-limit POST /api/v1/enroll is refused BEFORE the issue-nonce
// mint — flooding the unauthenticated surface must not mint Valkey keys.
func TestHandlerOverLimitDoesNotMintNonce(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, mr := newService(t, Config{CA: testCA(t), Names: st, Evidence: st, EnrollMinute: 1, EnrollHour: 100,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandler(t, svc, nil)

	// Exhaust the minute window for this IP.
	if e := svc.enrollLimit(context.Background(), "203.0.113.19"); e != nil {
		t.Fatalf("first limit draw must pass: %v", e)
	}
	keysBefore := len(mr.Keys())

	b, err := json.Marshal(enrollRequestBody{Nonce: "aabb", IdentityCSR: csrPEM(t, idCSR)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.19:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatalf("over-limit enroll must be refused, got %d", rr.Code)
	}
	if got := len(mr.Keys()); got != keysBefore {
		t.Fatalf("an over-limit enroll must NOT mint Valkey keys (%d -> %d)", keysBefore, got)
	}
}

func TestHandler_Health(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	banned := netip.MustParseAddr("203.0.113.13")
	tests := []struct {
		name     string
		life     fakeLifecycle
		remote   string
		wantCode int
		wantBody string
	}{
		{name: "serving", remote: "203.0.113.20:5000", wantCode: 200, wantBody: "ok\n"},
		{name: "stopping", life: fakeLifecycle{stopping: true}, remote: "203.0.113.20:5000", wantCode: 503, wantBody: "stopping\n"},
		{name: "draining", life: fakeLifecycle{stopping: true, draining: true}, remote: "203.0.113.20:5000", wantCode: 503, wantBody: "stopping\n"},
		{name: "banned peer", remote: "203.0.113.13:5000", wantCode: 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandlerLife(t, svc, func(a netip.Addr) bool { return a == banned }, tc.life)
			req := httptest.NewRequest("GET", "/api/v1/health", nil)
			req.RemoteAddr = tc.remote
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantCode {
				t.Fatalf("GET /api/v1/health = %d, want %d", rr.Code, tc.wantCode)
			}
			if tc.wantBody != "" && rr.Body.String() != tc.wantBody {
				t.Fatalf("body = %q, want %q", rr.Body.String(), tc.wantBody)
			}
		})
	}
	h := newTestHandlerLife(t, svc, nil, fakeLifecycle{})
	req := httptest.NewRequest("POST", "/api/v1/health", nil)
	req.RemoteAddr = "203.0.113.20:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("POST /api/v1/health = %d, want 404", rr.Code)
	}
}

func TestHandler_DrainingRefusesEnrollment(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	banned := netip.MustParseAddr("203.0.113.13")
	h := newTestHandlerLife(t, svc, func(a netip.Addr) bool { return a == banned }, fakeLifecycle{stopping: true, draining: true})
	for _, r := range []struct{ method, path string }{
		{"GET", "/api/v1/enroll/nonce"}, {"POST", "/api/v1/enroll"},
	} {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			req := httptest.NewRequest(r.method, r.path, bytes.NewReader([]byte("{}")))
			req.RemoteAddr = "203.0.113.20:5000"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != 503 {
				t.Fatalf("%s %s while draining = %d, want 503", r.method, r.path, rr.Code)
			}
			if rr.Header().Get("Connection") != "close" {
				t.Fatalf("Connection = %q, want close", rr.Header().Get("Connection"))
			}
			var body map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["reason"] != "draining" || body["retryable"] != true || body["retry_after_seconds"] != float64(1) {
				t.Fatalf("body = %v, want draining, retryable, retry_after_seconds 1", body)
			}
		})
	}
	req := httptest.NewRequest("GET", "/api/v1/enroll/nonce", nil)
	req.RemoteAddr = "203.0.113.13:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("a banned peer while draining = %d, want 403 (the ban check stays first)", rr.Code)
	}
	for _, r := range []struct{ method, path string }{{"GET", "/nope"}, {"GET", "/api/v1/enroll"}} {
		req := httptest.NewRequest(r.method, r.path, nil)
		req.RemoteAddr = "203.0.113.20:5000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 404 {
			t.Fatalf("%s %s while draining = %d, want the usual 404", r.method, r.path, rr.Code)
		}
	}
}

func TestHandler_StoppingStillServesEnrollment(t *testing.T) {
	st := tunneltest.NewStore()
	_, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	h := newTestHandlerLife(t, svc, nil, fakeLifecycle{stopping: true})
	req := httptest.NewRequest("GET", "/api/v1/enroll/nonce", nil)
	req.RemoteAddr = "203.0.113.20:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("the nonce route during the pre-drain = %d, want 200", rr.Code)
	}
}

func TestHandler_TracesOnlyRequestsThatWereNotRefused(t *testing.T) {
	t.Parallel()
	banned := netip.MustParseAddr("203.0.113.13")
	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		peer    string
		life    fakeLifecycle
		valkey  bool
		wantTxs int
	}{
		{name: "a served nonce", method: "GET", path: "/api/v1/enroll/nonce", peer: "198.51.100.20:5000", wantTxs: 1},
		{name: "a banned client", method: "GET", path: "/api/v1/enroll/nonce", peer: "203.0.113.13:5000", wantTxs: 0},
		{name: "a draining node", method: "GET", path: "/api/v1/enroll/nonce", peer: "198.51.100.20:5000",
			life: fakeLifecycle{draining: true}, wantTxs: 0},
		{name: "a malformed enrollment", method: "POST", path: "/api/v1/enroll", body: "{", peer: "198.51.100.20:5000", wantTxs: 0},
		{name: "a Valkey failure", method: "GET", path: "/api/v1/enroll/nonce", peer: "198.51.100.20:5000", valkey: true, wantTxs: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := tunneltest.NewStore()
			_, idPub := newCSR(t)
			svc, mr := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
				Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
			if tc.valkey {
				mr.SetError("valkey down")
			}
			h := newTestHandlerLife(t, svc, func(a netip.Addr) bool { return a == banned }, tc.life)
			rep, tr := tunneltest.NewReporter(t, 1)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = tc.peer
			rep.Handler(h, slog.New(slog.DiscardHandler), "enroll request", func(*http.Request) bool { return true }).
				ServeHTTP(httptest.NewRecorder(), req)
			rep.Flush(context.Background())
			if n := len(tr.Events("transaction")); n != tc.wantTxs {
				t.Fatalf("sent %d transactions, want %d", n, tc.wantTxs)
			}
		})
	}
}

func TestError_Refusal(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"internal", "name_unavailable", "identity_sign_failed", "acme_rate_limited", "acme_transient", "acme_failed"} {
		if (&Error{Reason: reason}).Refusal() {
			t.Errorf("%s reports work that failed, not a refusal", reason)
		}
	}
	for _, reason := range []string{"invalid_nonce", "enroll_rate", "unauthorized", "unsupported_key_type", "issuance_cap"} {
		if !(&Error{Reason: reason}).Refusal() {
			t.Errorf("%s is a refusal", reason)
		}
	}
}

func TestEnroll_PanicAfterTheClaimCarriesTheName(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
	rep, tr := tunneltest.NewReporter(t, 0)
	nonce := mintNonce(t, svc)
	var name string
	h := rep.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		res, ee := svc.Enroll(r.Context(), "198.51.100.21", Request{Nonce: nonce, IdentityCSR: idCSR})
		if ee != nil {
			t.Errorf("enroll: %v", ee)
			return
		}
		name = res.Name
		panic("boom after the claim")
	}), slog.New(slog.DiscardHandler), "enroll request", func(*http.Request) bool { return false })
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/enroll", nil))
	rep.Flush(context.Background())
	events := tr.Events("")
	if len(events) != 1 || name == "" || events[0].Tags["tunnel"] != name {
		t.Fatalf("want one panic event tagged with the claimed name %q, got %d events", name, len(events))
	}
}
