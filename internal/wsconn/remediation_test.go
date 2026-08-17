package wsconn

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

func TestHostSuffixOK(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"abc.example.test", true},
		{"abc.example.test:443", true},
		{"abc.example.test.", true},
		{"ABC.EXAMPLE.TEST", true},
		{"example.test", true},
		{"abc.attacker.example", false},
		{"abcexample.test", false},
	}
	for _, tc := range cases {
		if got := hostSuffixOK(tc.host, "example.test"); got != tc.ok {
			t.Errorf("hostSuffixOK(%q) = %v, want %v", tc.host, got, tc.ok)
		}
	}
}

func TestConnectRejectsForeignHostSuffix(t *testing.T) {
	h := newHarness(t, 0, nil)
	_, _, err := websocket.Dial(context.Background(), h.wsURL(), &websocket.DialOptions{Host: "abc.attacker.example"})
	if err == nil {
		t.Error("a Host outside the tunnel domain must be rejected before the upgrade")
	}
}

func TestConnectRateLimit429ReleasesSlot(t *testing.T) {
	h := newHarness(t, 0, func(c *config.ServeCmd) { c.LimitRPM = 1; c.LimitConnectPending = 4 })
	saw429 := 0
	for i := 0; i < 10; i++ {
		resp, err := http.Get(h.srv.URL + "/connect")
		if err != nil {
			t.Fatal(err)
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			t.Fatalf("attempt %d got 503 connect_pending — a 429 leaked the semaphore slot", i)
		}
		if code == http.StatusTooManyRequests {
			saw429++
		}
	}
	if saw429 == 0 {
		t.Error("expected rate_connect 429s with LimitRPM=1")
	}
}

func TestPreAuthSlotReleasedOnAuthFailure(t *testing.T) {
	h := newHarness(t, 0, func(c *config.ServeCmd) { c.LimitConnectPending = 1 })
	cert, key := h.issue(tName)
	for i := 0; i < 3; i++ {
		ws, nonce := rawDial(t, h.wsURL(), h.host(tName))
		// Sign over a WRONG nonce → possession fails → auth fails; the slot must be released.
		sendAuth(t, ws, base64.StdEncoding.EncodeToString(cert.Raw), signNonce(key, append([]byte("x"), nonce...)))
		_, _, _ = ws.Read(context.Background()) // wait for the server's close (auth resolved, slot freed)
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}
	// With LimitConnectPending=1, a valid connect after 3 sequential failures proves each slot freed.
	phone := h.connectPhone(tName, okHandler("ok"))
	_ = phone.Close()
	if h.rec.Count("reject", "connect_pending") != 0 {
		t.Errorf("no connect should have been refused as pending; got %d", h.rec.Count("reject", "connect_pending"))
	}
}

func TestMidSendDeadlineIs504(t *testing.T) {
	h := newHarness(t, wire.ChunkSize, nil) // burst = 32 KiB
	p := h.rawPhoneConnect(tName)
	defer func() { _ = p.ws.Close(websocket.StatusNormalClosure, "") }()
	// A foreign PacedByNode makes the WS leg PACE the upload. A large body at 32 KiB/s exceeds the
	// per-message deadline mid-send → Do returns nil (frontend maps to 504), NOT 502 tunnel_gone.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := routeReq(tName, "r1", "POST", "/mcp", bytes.Repeat([]byte("Z"), wire.ChunkSize*10))
	req.PacedByNode = "otherNode"
	if resp := h.mgr.RouteLocal(ctx, req); resp != nil {
		t.Errorf("mid-send deadline must yield nil (→504), got %+v", resp)
	}
}

func TestOversizedChunkTearsDown(t *testing.T) {
	// A below-ChunkSize burst so a normal-sized response chunk exceeds the burst — the reachable
	// ErrBurstExceeded case (a phone at the bandwidth floor sending a max-size frame).
	h := newHarness(t, 64, nil) // burst = 64 bytes
	p := h.rawPhoneConnect(tName)
	go func() { _ = h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "GET", "/mcp", nil)) }()
	reqid, _ := p.drainRequest()
	// Keep draining reads so the server's teardown close-handshake completes (a real client's read
	// loop always does this; without it p.ws.Read is idle and c.ws.Close blocks).
	go func() {
		for {
			if _, _, err := p.ws.Read(context.Background()); err != nil {
				return
			}
		}
	}()
	p.write(wire.RESPONSE_HEAD, wire.EncodeRespHeader(reqid, 200, nil), nil)
	// A 128-byte body chunk exceeds the 64-byte burst → ErrBurstExceeded → teardown.
	p.write(wire.RESPONSE_BODY_CHUNK, wire.EncodeReqIDHeader(reqid), bytes.Repeat([]byte("Y"), 128))
	waitRec(t, h.rec, "wsdisconnect", "oversized_frame", 1)
}

func TestEmptyBodyZeroChunksOnWire(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	go func() { _ = h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "POST", "/mcp", nil)) }()
	chunks := 0
	for {
		typ, _, _ := p.read()
		if typ == wire.REQUEST_BODY_CHUNK {
			chunks++
		}
		if typ == wire.REQUEST_END {
			break
		}
	}
	if chunks != 0 {
		t.Errorf("an empty body must send zero REQUEST_BODY_CHUNK frames, got %d", chunks)
	}
}

func TestBindDuringShutdownNoRouteSurvives(t *testing.T) {
	h := newHarness(t, 0, nil)
	phone := h.connectPhone(tName, okHandler("ok"))
	defer func() { _ = phone.Close() }()
	h.mgr.Shutdown()
	if _, _, ok, _ := h.reg.Lookup(context.Background(), tName); ok {
		t.Error("no route may survive manager.Shutdown")
	}
}

func TestOverCapResponsePacedAndAccounted(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	// A RESPONSE_BODY_CHUNK for a reqid with NO pending inflight: the read-pump paces + byte-accounts
	// the chunk BEFORE the inf==nil drop, and must NOT tear the tunnel down.
	payload := bytes.Repeat([]byte("Q"), 4096)
	p.write(wire.RESPONSE_BODY_CHUNK, wire.EncodeReqIDHeader("no-such-reqid"), payload)
	waitCond(t, func() bool { return h.rec.BytesFor(tName, "in") >= int64(len(payload)) },
		"a dropped unknown-reqid chunk must still be paced + byte-accounted")
	// The tunnel stays up: a real request still round-trips.
	respCh := make(chan *wire.RespEnvelope, 1)
	go func() { respCh <- h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "GET", "/mcp", nil)) }()
	reqid, _ := p.drainRequest()
	p.write(wire.RESPONSE_HEAD, wire.EncodeRespHeader(reqid, 200, nil), nil)
	p.write(wire.RESPONSE_END, wire.EncodeReqIDHeader(reqid), nil)
	if resp := <-respCh; resp == nil || resp.Status != 200 {
		t.Errorf("tunnel must stay up after dropping an unknown-reqid chunk; got %+v", resp)
	}
	if n := h.rec.Count("wsdisconnect", ""); n != 0 {
		t.Errorf("dropping an unknown-reqid chunk must not tear down; wsdisconnect=%d", n)
	}
}

func TestBanDuringConnectEvicts(t *testing.T) {
	h := newHarness(t, 0, nil)
	phone := h.connectPhone(tName, okHandler("ok"))
	defer func() { _ = phone.Close() }()
	v, _ := h.mgr.conns.Load(tName)
	conn := v.(*Conn)
	// A ban that lands AFTER conns.Store (the reload race the post-store re-check closes): the current
	// snapshot now bans the tunnel, so dropIfBanned must tear it down and unbind the route.
	h.loadBans("tunnel-name " + tName + "\n")
	if !h.mgr.dropIfBanned(conn) {
		t.Fatal("a conn banned after Store must be dropped by the post-store re-check")
	}
	waitRec(t, h.rec, "wsdisconnect", "banned_tunnel_name", 1)
	waitCond(t, func() bool {
		_, _, ok, _ := h.reg.Lookup(context.Background(), tName)
		return !ok
	}, "a banned-after-store conn's route must be removed")
}

func TestTeardownUnbindTimeBounded(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	defer func() { _ = p.ws.CloseNow() }()
	v, _ := h.mgr.conns.Load(tName)
	c := v.(*Conn)
	// Kill Redis: teardown's Unbind now fails. It MUST still return promptly (the 5s-bounded ctx guards
	// against an unresponsive Redis) and MUST log the failure rather than swallow it.
	h.mr.Close()
	done := make(chan struct{})
	go func() { c.teardown("dead_peer"); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("teardown did not return with an unresponsive Redis (Unbind not time-bounded)")
	}
	if !strings.Contains(h.logBuf.String(), "route unbind on teardown failed") {
		t.Errorf("teardown must log the unbind failure; log=%q", h.logBuf.String())
	}
}

func TestDeadPeerTeardown(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	// An abrupt close (no WS close handshake) is a dead peer, NOT a clean client close.
	_ = p.ws.CloseNow()
	waitRec(t, h.rec, "wsdisconnect", "dead_peer", 1)
	waitCond(t, func() bool {
		_, _, ok, _ := h.reg.Lookup(context.Background(), tName)
		return !ok
	}, "a dead peer's route must be removed")
}

func TestBindSurvivesRequestCtxCancel(t *testing.T) {
	h := newHarness(t, 0, nil)
	// A dedicated /connect endpoint that hands each request a cancellable context we can cancel from
	// the test, to prove the route/conn lifetime is the connection context (baseCtx-derived), NOT the
	// HTTP request context.
	reqCancel := make(chan context.CancelFunc, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Real-Ip", "203.0.113.50")
		ctx, cancel := context.WithCancel(r.Context())
		reqCancel <- cancel
		h.mgr.HandleConnect(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/connect"
	cert, key := h.issue(tName)
	phone, err := tunneltest.Dial(context.Background(), wsURL, h.host(tName), cert, key, okHandler("alive"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = phone.Close() }()
	h.waitBound(tName)
	// Cancel the REQUEST context: binding on it would tear the conn down here; the fix binds on the
	// connection context, so the route and the tunnel keep serving.
	(<-reqCancel)()
	waitCond(t, func() bool {
		if _, _, ok, _ := h.reg.Lookup(context.Background(), tName); !ok {
			return false
		}
		resp := h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "GET", "/mcp", nil))
		return resp != nil && resp.Status == 200 && string(resp.Body) == "alive"
	}, "route+conn must survive a cancelled request context")
}

func TestWSDropFailsPendingWith502(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	respCh := make(chan *wire.RespEnvelope, 1)
	go func() { respCh <- h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "GET", "/mcp", nil)) }()
	_, _ = p.drainRequest() // receive the request but never respond
	_ = p.ws.CloseNow()     // drop the WS mid-flight
	resp := <-respCh
	if resp == nil || resp.Status != http.StatusBadGateway || resp.ErrCode != "tunnel_gone" {
		t.Errorf("in-flight request on WS drop must resolve tunnel_gone/502, got %+v", resp)
	}
}

func TestSelfHealDoesNotClobberNewerConn(t *testing.T) {
	h := newHarness(t, 0, nil)
	phone := h.connectPhone(tName, okHandler("ok"))
	defer func() { _ = phone.Close() }()
	v, _ := h.mgr.conns.Load(tName)
	c := v.(*Conn)
	// A NEWER connection (same fingerprint, new connID) now owns the route. The stale conn's missing-
	// route self-heal must NOT clobber it: it must observe not-owner and tear itself down as superseded.
	if err := h.reg.Bind(context.Background(), tName, "nodeA", c.fp, "newerconn"); err != nil {
		t.Fatal(err)
	}
	if stop := c.selfHeal(); !stop {
		t.Error("self-heal against a newer conn's route must stop (superseded), not proceed")
	}
	waitRec(t, h.rec, "wsdisconnect", "superseded", 1)
	if got := h.mr.HGet("route:"+tName, "connID"); got != "newerconn" {
		t.Errorf("route connID = %q, want newerconn (a stale self-heal must not clobber the newer owner)", got)
	}
}

func TestStaleErrorFrameIgnored(t *testing.T) {
	h := newHarness(t, 0, nil)
	p := h.rawPhoneConnect(tName)
	respCh := make(chan *wire.RespEnvelope, 1)
	go func() { respCh <- h.mgr.RouteLocal(context.Background(), routeReq(tName, "r1", "GET", "/mcp", nil)) }()
	reqid, _ := p.drainRequest()
	// A stale ERROR for an UNKNOWN reqid must be dropped, not resolve the in-flight request.
	p.write(wire.ERROR, wire.EncodeErrorHeader("bogus-reqid", "stale"), nil)
	// The real response for the in-flight reqid still resolves normally.
	p.write(wire.RESPONSE_HEAD, wire.EncodeRespHeader(reqid, 200, nil), nil)
	p.write(wire.RESPONSE_END, wire.EncodeReqIDHeader(reqid), nil)
	if resp := <-respCh; resp == nil || resp.Status != 200 {
		t.Errorf("a stale ERROR must not disturb the in-flight request; got %+v", resp)
	}
}
