package router

import (
	"context"
	"testing"
	"time"
)

func TestRegistry_BindResetsByteFields(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1")
	if err := reg.AddTraffic(ctx, "abc", 100, 50); err != nil {
		t.Fatal(err)
	}
	// A fresh bind (new connID) MUST zero the byte fields — a reconnect never sums onto the old session.
	if err := reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn2"); err != nil {
		t.Fatal(err)
	}
	if in, out := mr.HGet("tunnel:abc", "bytes_in"), mr.HGet("tunnel:abc", "bytes_out"); in != "0" || out != "0" {
		t.Errorf("bytes after fresh bind = (%q, %q), want (0, 0)", in, out)
	}
}

func TestRegistry_AddTraffic_LiveKeyIncrements(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1") // TTL 30s
	mr.FastForward(20 * time.Second)                      // TTL now ~10s
	if err := reg.AddTraffic(ctx, "abc", 100, 50); err != nil {
		t.Fatal(err)
	}
	if err := reg.AddTraffic(ctx, "abc", 10, 0); err != nil {
		t.Fatal(err)
	}
	if in, out := mr.HGet("tunnel:abc", "bytes_in"), mr.HGet("tunnel:abc", "bytes_out"); in != "110" || out != "50" {
		t.Errorf("bytes after AddTraffic = (%q, %q), want (110, 50)", in, out)
	}
	// EXPIRE NX must NOT reset a live route's own TTL (would be ~30s again if it wrongly used PEXPIRE).
	if ttl := mr.TTL("tunnel:abc"); ttl > 15*time.Second {
		t.Errorf("AddTraffic reset a live route's TTL to %s (EXPIRE NX must no-op on a keyed TTL)", ttl)
	}
	// The route stays routable (node untouched).
	if _, _, _, ok, _ := reg.LookupRoute(ctx, "abc"); !ok {
		t.Error("AddTraffic must not clobber the route")
	}
}

func TestRegistry_AddTraffic_GoneKey_NonRoutableSelfExpiring(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	// No route bound: a post-disconnect flush lands on a gone key.
	if err := reg.AddTraffic(ctx, "abc", 100, 50); err != nil {
		t.Fatal(err)
	}
	// The created key is NON-routable (no `node` field) → LookupRoute reports ok=false.
	if _, _, _, ok, _ := reg.LookupRoute(ctx, "abc"); ok {
		t.Error("a byte-only orphan must not be routable")
	}
	// And it self-expires (EXPIRE NX gave it a TTL).
	if ttl := mr.TTL("tunnel:abc"); ttl <= 0 {
		t.Errorf("orphan TTL = %s, want > 0 (self-expiring)", ttl)
	}
}
