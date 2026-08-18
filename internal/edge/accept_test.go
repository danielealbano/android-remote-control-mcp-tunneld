package edge

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func baseConfig() Config {
	return Config{
		EnrollHost: "enroll.example.test", ControlHost: "connect.example.test", TunnelDomain: "example.test",
		MaxClients: 100, ConnRate: 100, Concurrent: 8, HandshakeTimeout: time.Second,
	}
}

func TestEdge_AdmitCeiling(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxClients = 2
	te := newTestEdge(t, cfg, nil, nil)
	first, second := te.e.admit(), te.e.admit()
	if !first || !second {
		t.Fatal("first two admits must succeed")
	}
	if te.e.admit() {
		t.Fatal("third admit must be refused past --max-clients")
	}
	te.e.release()
	if !te.e.admit() {
		t.Fatal("a released slot must be re-admittable")
	}
}

func TestEdge_HandleConn_BanFirst(t *testing.T) {
	banned := netip.MustParseAddr("198.51.100.9")
	te := newTestEdge(t, baseConfig(), func(ip netip.Addr) bool { return ip == banned }, nil)
	conn := newScriptConn("198.51.100.9", nil) // no ClientHello: ban must close BEFORE any peek
	te.e.clients.Add(1)
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() {
		t.Fatal("banned peer connection must be closed")
	}
	if !containsStr(te.rec.rejectReasons(), "ban") {
		t.Fatalf("want ban reject, got %v", te.rec.rejectReasons())
	}
}

func TestEdge_HandleConn_RateLimited(t *testing.T) {
	cfg := baseConfig()
	cfg.ConnRate = 0 // every connection over the (zero) rate
	te := newTestEdge(t, cfg, nil, nil)
	conn := newScriptConn("198.51.100.10", nil)
	te.e.clients.Add(1)
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() {
		t.Fatal("over-rate connection must be closed")
	}
	if !containsStr(te.rec.rejectReasons(), "conn-rate") {
		t.Fatalf("want conn-rate reject, got %v", te.rec.rejectReasons())
	}
}

func TestEdge_HandleConn_ReservedSNI_Local(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	rec := buildClientHello(cfg.ControlHost, []uint16{0x1301}, []extension{sniExt(cfg.ControlHost), alpnExt("h2"), supportedVersionsExt()})
	conn := newScriptConn("198.51.100.11", rec)
	te.e.clients.Add(1)
	go te.e.handleConn(context.Background(), conn)

	select {
	case c := <-te.e.controlLn.ch:
		// The pushed conn is a heldConn (max-clients slot holder) wrapping the metaConn carrier.
		hc, ok := c.(*heldConn)
		if !ok {
			t.Fatalf("pushed control conn must be a *heldConn holding the max-clients slot, got %T", c)
		}
		mc, ok := hc.NetConn().(*metaConn)
		if !ok {
			t.Fatalf("held conn must wrap a *metaConn carrying ConnMeta, got %T", hc.NetConn())
		}
		if mc.meta.SNI != cfg.ControlHost || mc.meta.JA4 == "" {
			t.Fatalf("pushed ConnMeta must carry SNI+JA4, got %+v", mc.meta)
		}
		before := te.e.clients.Load()
		_ = c.Close()
		if got := te.e.clients.Load(); got != before-1 {
			t.Fatalf("closing the pushed conn must release its max-clients slot (%d -> %d)", before, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserved control-host SNI must be pushed to the control listener")
	}
}

func TestEdge_HandleTunnel_UnknownRoute_Close(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	te.rtr.ok = false // no route
	conn := newScriptConn("198.51.100.12", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})
	if !conn.isClosed() {
		t.Fatal("unknown route must close the connection")
	}
	if !containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("want no-route reject, got %v", te.rec.rejectReasons())
	}
}

func TestEdge_HandleTunnel_RouteBan_Close(t *testing.T) {
	name := "abcdef012345.example.test"
	te := newTestEdge(t, baseConfig(), nil, func(n, fp string) bool { return true })
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"
	te.rtr.startedAt = time.Unix(1_700_000_000, 0)
	conn := newScriptConn("198.51.100.13", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: name})
	if !conn.isClosed() {
		t.Fatal("banned tunnel must close the connection")
	}
	if !containsStr(te.rec.rejectReasons(), "ban") {
		t.Fatalf("want ban reject, got %v", te.rec.rejectReasons())
	}
}
