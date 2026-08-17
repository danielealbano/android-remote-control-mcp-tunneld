package wsconn

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
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
