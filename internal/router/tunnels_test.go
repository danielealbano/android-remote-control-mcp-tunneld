package router

import (
	"context"
	"strings"
	"testing"
)

func TestRegistry_ScanTunnels_OneStepCursor(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if err := reg.BindRoute(ctx, n, "node1", "fp", "conn-"+n); err != nil {
			t.Fatal(err)
		}
	}
	// Iterate the cursor to completion, collecting names across the SCAN steps (prefix stripped).
	seen := map[string]bool{}
	var cursor uint64
	for {
		names, next, err := reg.ScanTunnels(ctx, cursor, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			seen[n] = true
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	if !seen["a"] || !seen["b"] || !seen["c"] {
		t.Errorf("ScanTunnels missed names: %v", seen)
	}
}

func TestRegistry_TunnelMeta_OmitsNonRoutable(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "live", "node1", "fp", "conn1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.AddTraffic(ctx, "live", 100, 50); err != nil {
		t.Fatal(err)
	}
	if err := reg.AddTraffic(ctx, "orphan", 7, 0); err != nil { // byte-only orphan (no node) → not routable
		t.Fatal(err)
	}
	meta, err := reg.TunnelMeta(ctx, []string{"live", "orphan", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 1 {
		t.Fatalf("TunnelMeta must report live routes only, got %v", meta)
	}
	m := meta["live"]
	if m.Node != "node1" || m.BytesIn != 100 || m.BytesOut != 50 {
		t.Errorf("live meta = %+v", m)
	}
	if _, ok := meta["orphan"]; ok {
		t.Error("a byte-only orphan (no node) must be omitted")
	}
}

func TestRegistry_TunnelMeta_LogsMalformedCounter(t *testing.T) {
	reg, mr, _, buf := newLoggedReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "live", "node1", "fp", "conn1"); err != nil {
		t.Fatal(err)
	}
	mr.HSet(key("live"), "bytes_in", "not-a-number", "bytes_out", "9")
	meta, err := reg.TunnelMeta(ctx, []string{"live"})
	if err != nil {
		t.Fatal(err)
	}
	if m := meta["live"]; m.BytesIn != 0 || m.BytesOut != 9 {
		t.Fatalf("meta = %+v, want the malformed counter reported as 0", m)
	}
	if !strings.Contains(buf.String(), `msg="unparseable route byte counter (reported as 0)" tunnel=live`) {
		t.Fatalf("the malformed counter must be logged; log = %q", buf.String())
	}
}

func TestRegistry_AtoiVal_UnexpectedTypeLogged(t *testing.T) {
	reg, _, _, buf := newLoggedReg(t)
	if got := reg.atoiVal("n", int64(5)); got != 0 {
		t.Fatalf("atoiVal(int64) = %d, want 0", got)
	}
	if !strings.Contains(buf.String(), `msg="unexpected route byte counter type (reported as 0)" tunnel=n type=int64`) {
		t.Fatalf("an unexpected counter type must be logged; log = %q", buf.String())
	}
}
