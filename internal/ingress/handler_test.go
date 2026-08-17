package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ban"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
	"github.com/redis/go-redis/v9"
)

// failPublish wraps a real client but makes Publish error, to exercise the publish-failure → 502 path.
type failPublish struct{ redis.UniversalClient }

func (f failPublish) Publish(ctx context.Context, channel string, message any) *redis.IntCmd {
	c := redis.NewIntCmd(ctx)
	c.SetErr(errors.New("publish failed"))
	return c
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const iName = "abcname2345"

type ih struct {
	t       *testing.T
	mr      *miniredis.Miniredis
	rdb     *redis.Client
	reg     *router.Registry
	ban     *ban.Engine
	buckets *limit.BucketRegistry
	rec     *tunneltest.Recorder
	h       *Handler
	node    string

	mu      sync.Mutex
	lastReq *wire.ReqEnvelope
}

func newIngress(t *testing.T, bps int64, tweak func(*config.ServeCmd)) *ih {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cfg := config.ServeCmd{
		ClientIPHeader:      "X-Real-Ip",
		LimitRPS:            10,
		LimitRPM:            100,
		LimitConcurrent:     4,
		LimitBody:           "1mb",
		LimitResponse:       "10mb",
		LimitHeaders:        "16kb",
		LimitHeaderSingle:   "8kb",
		LimitRequestTimeout: 60 * time.Second,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	if bps == 0 {
		bps = 100 * 1024 * 1024
	}
	reg := router.NewRegistry(rdb, 30*time.Second)
	banEng := ban.NewEngine()
	buckets := limit.NewBucketRegistry(bps)
	rec := &tunneltest.Recorder{}
	h, err := NewHandler(cfg, "nodeA", rdb, banEng, reg, buckets, rec, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	return &ih{t: t, mr: mr, rdb: rdb, reg: reg, ban: banEng, buckets: buckets, rec: rec, h: h, node: "nodeA"}
}

func (x *ih) bind(name string) {
	if err := x.reg.Bind(context.Background(), name, x.node, "sha256:fp", "conn1"); err != nil {
		x.t.Fatal(err)
	}
}

func (x *ih) loadBans(content string) {
	dir := x.t.TempDir()
	f := dir + "/bans.txt"
	if err := writeFile(f, content); err != nil {
		x.t.Fatal(err)
	}
	if err := x.ban.Load([]string{f}, "", discardLog()); err != nil {
		x.t.Fatal(err)
	}
}

// startEcho subscribes to req:{node} (confirmed) and replies with a canned response, capturing the
// forwarded envelope for inspection.
func (x *ih) startEcho(status int, body string, respHdr http.Header) {
	x.t.Helper()
	ctx := context.Background()
	pubsub := x.rdb.Subscribe(ctx, "req:"+x.node)
	if _, err := pubsub.Receive(ctx); err != nil {
		x.t.Fatal(err)
	}
	x.t.Cleanup(func() { _ = pubsub.Close() })
	go func() {
		for msg := range pubsub.Channel() {
			req, err := wire.UnmarshalReq([]byte(msg.Payload))
			if err != nil {
				continue
			}
			x.mu.Lock()
			x.lastReq = req
			x.mu.Unlock()
			resp := &wire.RespEnvelope{ReqID: req.ReqID, Status: status, Header: respHdr, Body: []byte(body)}
			_ = x.rdb.Publish(ctx, "resp:"+req.ReqID, wire.MarshalResp(resp)).Err()
		}
	}()
}

func (x *ih) forwarded() *wire.ReqEnvelope {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.lastReq
}

type reqOpt func(*http.Request)

func (x *ih) do(method, host, path string, body []byte, opts ...reqOpt) *httptest.ResponseRecorder {
	x.t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, "http://"+host+path, nil)
	} else {
		r = httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	}
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	for _, o := range opts {
		o(r)
	}
	rr := httptest.NewRecorder()
	x.h.ServeHTTP(rr, r)
	return rr
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withIP(ip string) reqOpt {
	return func(r *http.Request) {
		if ip == "" {
			r.Header.Del("X-Real-Ip")
		} else {
			r.Header.Set("X-Real-Ip", ip)
		}
	}
}

func host(name string) string { return name + ".example.test" }

func TestForwardsMcpPostWithAndWithoutAuth(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "app-response", nil)
	// With Authorization.
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`), withHeader("Authorization", "Bearer x"))
	if rr.Code != 200 || rr.Body.String() != "app-response" {
		t.Errorf("authed POST /mcp = %d %q", rr.Code, rr.Body.String())
	}
	// Token-less POST /mcp is forwarded unchanged (edge never inspects Authorization).
	rr2 := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr2.Code != 200 {
		t.Errorf("token-less POST /mcp = %d, want forwarded 200", rr2.Code)
	}
}

func TestGetMcpIs405AtEdge(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	rr := x.do("GET", host(iName), "/mcp", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /mcp = %d, want 405", rr.Code)
	}
	if rr.Header().Get("Allow") != "POST, DELETE" {
		t.Errorf("Allow header = %q", rr.Header().Get("Allow"))
	}
	if x.rec.Count("reject", "method_denied") != 1 {
		t.Error("method_denied not recorded")
	}
}

func TestOptionsForwarded(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(204, "", nil)
	rr := x.do("OPTIONS", host(iName), "/mcp", nil)
	if rr.Code != 204 {
		t.Errorf("OPTIONS /mcp = %d, want forwarded 204", rr.Code)
	}
}

func TestOAuthEndpointsNeedNoAuth(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	for _, p := range []struct{ m, path string }{
		{"POST", "/register"}, {"GET", "/authorize"}, {"POST", "/token"},
		{"GET", "/.well-known/oauth-protected-resource"},
	} {
		rr := x.do(p.m, host(iName), p.path, nil)
		if rr.Code != 200 {
			t.Errorf("%s %s = %d, want forwarded", p.m, p.path, rr.Code)
		}
	}
}

func TestSharePathRegex(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "file", nil)
	good := "/s/" + repeat("a", 64)
	if rr := x.do("GET", host(iName), good, nil); rr.Code != 200 {
		t.Errorf("valid share path = %d", rr.Code)
	}
	if rr := x.do("GET", host(iName), "/s/"+repeat("a", 63), nil); rr.Code != 404 {
		t.Errorf("bad share path = %d, want 404", rr.Code)
	}
}

func TestNonAllowlisted404(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	rr := x.do("GET", host(iName), "/", nil)
	if rr.Code != 404 || x.rec.Count("reject", "path_denied") != 1 {
		t.Errorf("GET / = %d, path_denied=%d", rr.Code, x.rec.Count("reject", "path_denied"))
	}
}

func TestBannedTunnel403AtIngress(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.loadBans("tunnel-name " + iName + "\n")
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != 403 || x.rec.Count("reject", "banned_tunnel_name") != 1 {
		t.Errorf("banned tunnel = %d", rr.Code)
	}
}

func TestBannedIP403First(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.loadBans("ip 203.0.113.7\n")
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != 403 || x.rec.Count("reject", "banned_ip") != 1 {
		t.Errorf("banned ip = %d", rr.Code)
	}
}

func TestSpoofedXFFIgnoredForIPKey(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.ClientIPHeader = "X-Forwarded-For" })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	x.loadBans("ip 1.2.3.4\n") // the SPOOFED left-most entry
	// Key must use the right-most (proxy) hop 9.9.9.9 → NOT banned → forwarded.
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`),
		func(r *http.Request) { r.Header.Del("X-Real-Ip"); r.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9") })
	if rr.Code == 403 {
		t.Error("must key on the right-most XFF entry, not the spoofed left one")
	}
}

func TestMissingClientIP400(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`), withIP(""))
	if rr.Code != 400 || x.rec.Count("reject", "missing_client_ip") != 1 {
		t.Errorf("missing client ip = %d", rr.Code)
	}
}

func TestPublicClientCertHeader400(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`), withHeader("X-Forwarded-Tls-Client-Cert", "MIIB..."))
	if rr.Code != 400 || x.rec.Count("reject", "public_mtls_header") != 1 {
		t.Errorf("mtls header = %d", rr.Code)
	}
}

func TestForwardedHeadersSanitized(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	x.do("POST", host(iName), "/mcp", []byte(`{}`),
		withHeader("X-Forwarded-Proto", "https"),
		withHeader("Connection", "keep-alive"),
		withHeader("X-Forwarded-Server", "evil"))
	env := x.forwarded()
	if env == nil {
		t.Fatal("no forwarded request captured")
	}
	if env.Header.Get("X-Forwarded-Proto") != "https" {
		t.Error("proxy X-Forwarded-Proto must be forwarded")
	}
	if env.Header.Get("Connection") != "" {
		t.Error("hop-by-hop Connection must be stripped")
	}
	if env.Header.Get("X-Forwarded-Server") != "" {
		t.Error("client X-Forwarded-Server must be dropped")
	}
}

func TestResponseHopByHopStripped(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "ok", http.Header{"Connection": {"close"}, "Content-Type": {"text/plain"}})
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Header().Get("Connection") != "" {
		t.Error("response hop-by-hop Connection must be stripped")
	}
	if rr.Header().Get("Content-Type") != "text/plain" {
		t.Error("normal response header must pass through")
	}
}

func TestBodyOverCap413(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitBody = "1kb" })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	rr := x.do("POST", host(iName), "/mcp", repeatBytes('A', 2048))
	if rr.Code != http.StatusRequestEntityTooLarge || x.rec.Count("reject", "body_too_large") != 1 {
		t.Errorf("body over cap = %d", rr.Code)
	}
}

func TestChunkedBodyOverCap413(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitBody = "1kb" })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", bytes.NewReader(repeatBytes('B', 4096)))
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	r.ContentLength = -1 // unknown length → MaxBytesReader bounds actual bytes
	r.Header.Del("Content-Length")
	rr := httptest.NewRecorder()
	x.h.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked body over cap = %d, want 413", rr.Code)
	}
}

func TestDeclaredOversizeContentLength413WithoutRead(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitBody = "1kb" })
	x.bind(iName)
	tracker := &readTracker{}
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", tracker)
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	r.ContentLength = 1 << 20 // declared 1MB > 1kb cap
	rr := httptest.NewRecorder()
	x.h.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared oversize CL = %d, want 413", rr.Code)
	}
	if tracker.read {
		t.Error("body must NOT be read on a declared-oversize Content-Length")
	}
}

func TestTotalAndSingleHeaderOverCap431(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitHeaderSingle = "1kb"; c.LimitHeaders = "2kb" })
	x.bind(iName)
	// Single header over 1kb.
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`), withHeader("X-Big", repeat("z", 2000)))
	if rr.Code != http.StatusRequestHeaderFieldsTooLarge || x.rec.Count("reject", "headers_too_large") == 0 {
		t.Errorf("single header over cap = %d", rr.Code)
	}
}

func TestRPSRPM429WithRetryAfter(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitRPS = 2 })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	var last *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		last = x.do("POST", host(iName), "/mcp", []byte(`{}`))
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request = %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("Retry-After missing")
	}
	if x.rec.Count("reject", "rate_rps") < 1 {
		t.Error("rate_rps not recorded")
	}
}

func TestConcurrency429(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitConcurrent = 1 })
	x.bind(iName)
	// Occupy the only slot with a never-answered request.
	_ = x.mr.Set("conc:"+iName, "1")
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != http.StatusTooManyRequests || x.rec.Count("reject", "concurrency") != 1 {
		t.Errorf("concurrency = %d", rr.Code)
	}
}

func TestTimeout504(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitRequestTimeout = 250 * time.Millisecond })
	x.bind(iName)
	// No responder → RoundTrip times out.
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != http.StatusGatewayTimeout {
		t.Errorf("timeout = %d, want 504", rr.Code)
	}
	if x.rec.Count("timeout", "") != 1 || x.rec.Count("reject", "timeout") != 1 {
		t.Errorf("timeout writers: timeout=%d reject=%d", x.rec.Count("timeout", ""), x.rec.Count("reject", "timeout"))
	}
}

func TestOffline502(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	// Responder returns a tunnel_gone envelope (WS dropped mid-round-trip).
	ctx := context.Background()
	pubsub := x.rdb.Subscribe(ctx, "req:"+x.node)
	_, _ = pubsub.Receive(ctx)
	t.Cleanup(func() { _ = pubsub.Close() })
	go func() {
		for msg := range pubsub.Channel() {
			req, _ := wire.UnmarshalReq([]byte(msg.Payload))
			resp := &wire.RespEnvelope{ReqID: req.ReqID, Status: 502, ErrCode: "tunnel_gone"}
			_ = x.rdb.Publish(ctx, "resp:"+req.ReqID, wire.MarshalResp(resp)).Err()
		}
	}()
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != http.StatusBadGateway || x.rec.Count("reject", "tunnel_offline") != 1 {
		t.Errorf("offline = %d", rr.Code)
	}
}

func TestUnknownHost404(t *testing.T) {
	x := newIngress(t, 0, nil)
	rr := x.do("POST", host("nobody999"), "/mcp", []byte(`{}`))
	if rr.Code != 404 || x.rec.Count("reject", "unknown_host") != 1 {
		t.Errorf("unknown host = %d", rr.Code)
	}
}

func TestInflightAddSubPaired(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if x.rec.Count("inflight", "") != 2 {
		t.Errorf("expected inflight +1/-1 (2 calls), got %d", x.rec.Count("inflight", ""))
	}
}

func TestSlowBodyRead408ReleasesSlot(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitRequestTimeout = 200 * time.Millisecond })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	// A body that blocks forever until closed → the end-to-end deadline fires → 408.
	bb := &blockingBody{done: make(chan struct{})}
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", bb)
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	r.ContentLength = -1
	rr := httptest.NewRecorder()
	x.h.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestTimeout || x.rec.Count("reject", "body_read_timeout") != 1 {
		t.Errorf("slow body = %d", rr.Code)
	}
	// The concurrency slot must have been released — a follow-up request Acquires and forwards.
	rr2 := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr2.Code == http.StatusTooManyRequests {
		t.Error("concurrency slot was not released after 408")
	}
}

func TestSanitize_ConnectionNominatedStripped(t *testing.T) {
	out, rejected := Sanitize(http.Header{"Connection": {"X-Custom"}, "X-Custom": {"v"}, "Content-Type": {"application/json"}})
	if rejected {
		t.Fatal("unexpected rejection")
	}
	if out.Get("X-Custom") != "" {
		t.Error("a Connection-nominated header must be stripped")
	}
	if out.Get("Connection") != "" {
		t.Error("Connection must be stripped")
	}
	if out.Get("Content-Type") != "application/json" {
		t.Error("a normal header must pass through")
	}
	rout := SanitizeResponse(http.Header{"Connection": {"X-Trailer"}, "X-Trailer": {"v"}, "Content-Type": {"text/plain"}})
	if rout.Get("X-Trailer") != "" {
		t.Error("a response Connection-nominated header must be stripped")
	}
}

func TestSanitize_MTLSAndForwarded(t *testing.T) {
	for _, h := range []string{"X-Forwarded-Tls-Client-Cert", "X-Forwarded-Tls-Client-Cert-Info", "Ssl-Client-Cert", "X-Client-Cert", "X-Ssl-Client-Cert"} {
		if _, rejected := Sanitize(http.Header{h: {"cert"}}); !rejected {
			t.Errorf("mTLS header %q must be rejected", h)
		}
	}
	out, rejected := Sanitize(http.Header{
		"Forwarded":          {"for=1.2.3.4"},
		"X-Forwarded-For":    {"9.9.9.9"},
		"X-Forwarded-Proto":  {"https"},
		"X-Forwarded-Host":   {"h.example.test"},
		"X-Forwarded-Server": {"evil"},
	})
	if rejected {
		t.Fatal("unexpected rejection")
	}
	if out.Get("Forwarded") != "" || out.Get("X-Forwarded-Server") != "" {
		t.Error("RFC Forwarded and client X-Forwarded-* must be dropped")
	}
	if out.Get("X-Forwarded-Proto") != "https" || out.Get("X-Forwarded-Host") != "h.example.test" || out.Get("X-Forwarded-For") != "9.9.9.9" {
		t.Error("proxy X-Forwarded-Proto/Host/For must be re-added")
	}
}

func TestFirstLabel_CaseInsensitive(t *testing.T) {
	cases := map[string]string{
		"ABC.example.test":     "abc",
		"Abc.example.test:443": "abc",
		"abc.example.test.":    "abc",
		"ABC":                  "abc",
	}
	for h, want := range cases {
		if got := firstLabel(h); got != want {
			t.Errorf("firstLabel(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestTotalHeaderCap431(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitHeaderSingle = "8kb"; c.LimitHeaders = "2kb" })
	x.bind(iName)
	opts := []reqOpt{}
	for i := 0; i < 20; i++ { // 20 × ~205 bytes ≈ 4 kb total (> 2 kb), each < 8 kb single
		opts = append(opts, withHeader(fmt.Sprintf("X-H-%d", i), repeat("z", 200)))
	}
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`), opts...)
	if rr.Code != http.StatusRequestHeaderFieldsTooLarge || x.rec.Count("reject", "headers_too_large") == 0 {
		t.Errorf("total headers over cap = %d, want 431 headers_too_large", rr.Code)
	}
}

func TestRateRPM429(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitRPM = 1; c.LimitRPS = 100 })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	saw429 := false
	for i := 0; i < 5; i++ { // 5 quick requests cannot span two 60s windows → at least one 429
		if x.do("POST", host(iName), "/mcp", []byte(`{}`)).Code == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	if !saw429 {
		t.Error("with LimitRPM=1 a burst of 5 must trip 429")
	}
	if x.rec.Count("reject", "rate_rpm") < 1 {
		t.Error("rate_rpm reason not recorded")
	}
}

func TestPacedByNodeStamped(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	x.do("POST", host(iName), "/mcp", []byte(`{}`))
	env := x.forwarded()
	if env == nil {
		t.Fatal("no forwarded request captured")
	}
	if env.PacedByNode != "nodeA" {
		t.Errorf("PacedByNode = %q, want nodeA", env.PacedByNode)
	}
}

func TestLimiterRedisError500(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	x.mr.Close() // Redis down → a Redis-backed check errors → 500 (logged)
	rr := x.do("POST", host(iName), "/mcp", []byte(`{}`))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Redis error = %d, want 500", rr.Code)
	}
}

func TestPublishFailure502(t *testing.T) {
	mr := miniredis.RunT(t)
	real := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = real.Close() })
	rdb := failPublish{real}
	cfg := config.ServeCmd{
		ClientIPHeader: "X-Real-Ip", LimitRPS: 10, LimitRPM: 100, LimitConcurrent: 4,
		LimitBody: "1mb", LimitResponse: "10mb", LimitHeaders: "16kb", LimitHeaderSingle: "8kb",
		LimitRequestTimeout: 5 * time.Second,
	}
	reg := router.NewRegistry(rdb, 30*time.Second)
	rec := &tunneltest.Recorder{}
	h, err := NewHandler(cfg, "nodeA", rdb, ban.NewEngine(), reg, limit.NewBucketRegistry(100*1024*1024), rec, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Bind(context.Background(), iName, "nodeA", "sha256:fp", "conn1"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", bytes.NewReader([]byte(`{}`)))
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("publish failure = %d, want 502", rr.Code)
	}
	if rec.Count("publisherror", "") < 1 {
		t.Error("PublishError not recorded")
	}
}

func TestClientAbortNotTimeout(t *testing.T) {
	x := newIngress(t, 0, nil)
	x.bind(iName)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", bytes.NewReader([]byte(`{}`))).WithContext(ctx)
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	x.h.ServeHTTP(httptest.NewRecorder(), r)
	if x.rec.Count("timeout", "") != 0 || x.rec.Count("reject", "timeout") != 0 {
		t.Errorf("a client abort must record no timeout: timeout=%d reject=%d",
			x.rec.Count("timeout", ""), x.rec.Count("reject", "timeout"))
	}
}

func TestBodyTimeoutNoWriterRace(t *testing.T) {
	x := newIngress(t, 0, func(c *config.ServeCmd) { c.LimitRequestTimeout = 100 * time.Millisecond })
	x.bind(iName)
	x.startEcho(200, "ok", nil)
	bb := &blockingBody{done: make(chan struct{})}
	r := httptest.NewRequest("POST", "http://"+host(iName)+"/mcp", bb)
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	r.ContentLength = -1
	rr := httptest.NewRecorder()
	x.h.ServeHTTP(rr, r) // under -race: the body goroutine must never touch w
	if rr.Code != http.StatusRequestTimeout {
		t.Errorf("slow-body timeout = %d, want 408", rr.Code)
	}
}

// --- helpers ---

func repeat(s string, n int) string { return string(repeatBytes(s[0], n)) }

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func repeatBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

type readTracker struct{ read bool }

func (r *readTracker) Read(p []byte) (int, error) { r.read = true; return 0, io.EOF }
func (r *readTracker) Close() error               { return nil }

type blockingBody struct {
	done chan struct{}
	once sync.Once
}

func (b *blockingBody) Read(p []byte) (int, error) {
	<-b.done
	return 0, errors.New("body closed")
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.done) })
	return nil
}
