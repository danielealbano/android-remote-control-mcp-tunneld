package router

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newReg(t *testing.T) (*Registry, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRegistry(rdb, 30*time.Second), mr
}

func TestBindRouteThenLookup(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "sha256:fp1", "conn1"); err != nil {
		t.Fatal(err)
	}
	node, fp, cid, ok, err := reg.LookupRoute(ctx, "abc")
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if node != "nodeA" || fp != "sha256:fp1" || cid != "conn1" {
		t.Errorf("lookup = (%q,%q,%q), want (nodeA, sha256:fp1, conn1)", node, fp, cid)
	}
	if _, _, _, ok, _ := reg.LookupRoute(ctx, "missing"); ok {
		t.Error("unbound name must not resolve")
	}
}

func TestBindRouteRejectsDifferentFingerprint(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "sha256:fp1", "conn1")
	if err := reg.BindRoute(ctx, "abc", "nodeB", "sha256:DIFFERENT", "conn2"); err != ErrNameHeldByOther {
		t.Errorf("different fingerprint bind: err = %v, want ErrNameHeldByOther", err)
	}
}

// TestRegistry_BindRoute_ConnIDCollisionRerolls covers the connID-collision re-roll signal: a bind
// whose connID equals the currently-stored one returns ErrConnIDCollision; a distinct connID rebinds.
func TestRegistry_BindRoute_ConnIDCollisionRerolls(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1"); err != ErrConnIDCollision {
		t.Fatalf("colliding connID bind: err = %v, want ErrConnIDCollision", err)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn2"); err != nil {
		t.Fatalf("distinct connID bind: %v", err)
	}
	if _, _, cid, ok, _ := reg.LookupRoute(ctx, "abc"); !ok || cid != "conn2" {
		t.Errorf("route connID = %q ok=%v, want conn2", cid, ok)
	}
}

func TestHeartbeatRefreshesTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1")
	mr.FastForward(20 * time.Second) // TTL now ~10s
	res, err := reg.Heartbeat(ctx, "abc", "conn1")
	if err != nil || res != HeartbeatRefreshed {
		t.Fatalf("heartbeat: res=%v err=%v", res, err)
	}
	if ttl := mr.TTL("route:abc"); ttl < 25*time.Second {
		t.Errorf("TTL after refresh = %s, want ~30s", ttl)
	}
}

func TestUnbindRemovesRoute(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1")
	if err := reg.Unbind(ctx, "abc", "conn1"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok, _ := reg.LookupRoute(ctx, "abc"); ok {
		t.Error("route must be gone after unbind")
	}
}

func TestUnbindIsConnConditional(t *testing.T) {
	ctx := context.Background()
	for _, node2 := range []string{"nodeB", "nodeA"} { // another node AND the same node
		reg, _ := newReg(t)
		_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1")
		if err := reg.BindRoute(ctx, "abc", node2, "fp", "conn2"); err != nil {
			t.Fatal(err)
		}
		// The stale conn1 tears down — must NOT clobber conn2's route.
		if err := reg.Unbind(ctx, "abc", "conn1"); err != nil {
			t.Fatal(err)
		}
		node, _, _, ok, _ := reg.LookupRoute(ctx, "abc")
		if !ok || node != node2 {
			t.Errorf("node2=%s: after stale unbind, route = (%q, ok=%v), want %s", node2, node, ok, node2)
		}
	}
}

func TestHeartbeatIsConnConditional(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn1")
	_ = reg.BindRoute(ctx, "abc", "nodeB", "fp", "conn2") // rebind to conn2
	ttlBefore := mr.TTL("route:abc")
	res, err := reg.Heartbeat(ctx, "abc", "conn1") // stale conn heartbeat
	if err != nil {
		t.Fatal(err)
	}
	if res != HeartbeatNotOwner {
		t.Errorf("stale heartbeat = %v, want HeartbeatNotOwner", res)
	}
	node, _, _, _, _ := reg.LookupRoute(ctx, "abc")
	if node != "nodeB" {
		t.Errorf("owner changed by stale heartbeat: %q", node)
	}
	if ttl := mr.TTL("route:abc"); ttl > ttlBefore {
		t.Error("stale heartbeat must not refresh TTL")
	}
}

func TestBindRouteIfAbsentOrOwner_ThreeState(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeA", "fp", "conn1"); err != nil || res != SelfHealBound {
		t.Fatalf("absent → bound: res=%v err=%v", res, err)
	}
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeA", "fp", "conn1"); err != nil || res != SelfHealBound {
		t.Fatalf("same connID → bound: res=%v err=%v", res, err)
	}
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeB", "fp", "conn2"); err != nil || res != SelfHealNotOwner {
		t.Fatalf("different connID (same fp) → not-owner: res=%v err=%v", res, err)
	}
	if node, _, _, _, _ := reg.LookupRoute(ctx, "abc"); node != "nodeA" {
		t.Errorf("a not-owner self-heal must not clobber the route: node=%q", node)
	}
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeC", "DIFFERENT", "conn3"); res != SelfHealConflict || err != ErrNameHeldByOther {
		t.Errorf("different fingerprint → conflict: res=%v err=%v, want SelfHealConflict/ErrNameHeldByOther", res, err)
	}
}

func TestHeartbeatDistinguishesMissingFromNotOwner(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if res, _ := reg.Heartbeat(ctx, "gone", "conn1"); res != HeartbeatMissing {
		t.Errorf("missing route heartbeat = %v, want HeartbeatMissing", res)
	}
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp", "conn2")
	if res, _ := reg.Heartbeat(ctx, "abc", "conn1"); res != HeartbeatNotOwner {
		t.Errorf("other-owner heartbeat = %v, want HeartbeatNotOwner", res)
	}
}
