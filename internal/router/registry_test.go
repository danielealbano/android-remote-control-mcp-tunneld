package router

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func newReg(t *testing.T) (*Registry, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	reg, err := NewRegistry(rdb, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return reg, mr
}

func TestBindRouteThenLookup(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	node, cid, ok, err := reg.LookupRoute(ctx, "abc")
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if node != "nodeA" || cid != "conn1" {
		t.Errorf("lookup = (%q,%q), want (nodeA, conn1)", node, cid)
	}
	if _, _, ok, err := reg.LookupRoute(ctx, "missing"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Error("unbound name must not resolve")
	}
}

func TestBindRoute_NewConnectionReplacesOwner(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	mr.HSet("tunnel:abc", "bytes_in", "100", "bytes_out", "200")
	if err := reg.BindRoute(ctx, "abc", "nodeB", "conn2"); err != nil {
		t.Fatalf("a new connection must replace the owner: %v", err)
	}
	node, cid, ok, err := reg.LookupRoute(ctx, "abc")
	if err != nil || !ok || node != "nodeB" || cid != "conn2" {
		t.Fatalf("lookup = (%q, %q, ok=%v, err=%v), want (nodeB, conn2)", node, cid, ok, err)
	}
	if in, out := mr.HGet("tunnel:abc", "bytes_in"), mr.HGet("tunnel:abc", "bytes_out"); in != "0" || out != "0" {
		t.Errorf("a new owner must start with zeroed byte fields, got in=%q out=%q", in, out)
	}
}

func TestBindRoute_WritesOnlyRoutingFields(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.BindRouteIfAbsentOrOwner(ctx, "def", "nodeA", "conn2"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tunnel:abc", "tunnel:def"} {
		fields, err := mr.HKeys(k)
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(fields)
		if want := []string{"bytes_in", "bytes_out", "connID", "node"}; !slices.Equal(fields, want) {
			t.Errorf("%s fields = %v, want %v", k, fields, want)
		}
	}
}

// TestRegistry_BindRoute_ConnIDCollisionRerolls covers the connID-collision re-roll signal: a bind
// whose connID equals the currently-stored one returns ErrConnIDCollision; a distinct connID rebinds.
func TestRegistry_BindRoute_ConnIDCollisionRerolls(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != ErrConnIDCollision {
		t.Fatalf("colliding connID bind: err = %v, want ErrConnIDCollision", err)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn2"); err != nil {
		t.Fatalf("distinct connID bind: %v", err)
	}
	if _, cid, ok, err := reg.LookupRoute(ctx, "abc"); err != nil {
		t.Fatal(err)
	} else if !ok || cid != "conn2" {
		t.Errorf("route connID = %q ok=%v, want conn2", cid, ok)
	}
}

func TestHeartbeatRefreshesTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(20 * time.Second) // TTL now ~10s
	res, err := reg.Heartbeat(ctx, "abc", "conn1")
	if err != nil || res != HeartbeatRefreshed {
		t.Fatalf("heartbeat: res=%v err=%v", res, err)
	}
	if ttl := mr.TTL("tunnel:abc"); ttl < 25*time.Second {
		t.Errorf("TTL after refresh = %s, want ~30s", ttl)
	}
}

func TestUnbindRemovesRoute(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Unbind(ctx, "abc", "conn1"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := reg.LookupRoute(ctx, "abc"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Error("route must be gone after unbind")
	}
}

func TestUnbindIsConnConditional(t *testing.T) {
	ctx := context.Background()
	for _, node2 := range []string{"nodeB", "nodeA"} { // another node AND the same node
		reg, _ := newReg(t)
		if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
			t.Fatal(err)
		}
		if err := reg.BindRoute(ctx, "abc", node2, "conn2"); err != nil {
			t.Fatal(err)
		}
		// The stale conn1 tears down — must NOT clobber conn2's route.
		if err := reg.Unbind(ctx, "abc", "conn1"); err != nil {
			t.Fatal(err)
		}
		node, _, ok, err := reg.LookupRoute(ctx, "abc")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || node != node2 {
			t.Errorf("node2=%s: after stale unbind, route = (%q, ok=%v), want %s", node2, node, ok, node2)
		}
	}
}

func TestHeartbeatIsConnConditional(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeB", "conn2"); err != nil { // rebind to conn2
		t.Fatal(err)
	}
	ttlBefore := mr.TTL("tunnel:abc")
	res, err := reg.Heartbeat(ctx, "abc", "conn1") // stale conn heartbeat
	if err != nil {
		t.Fatal(err)
	}
	if res != HeartbeatNotOwner {
		t.Errorf("stale heartbeat = %v, want HeartbeatNotOwner", res)
	}
	node, _, _, err := reg.LookupRoute(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if node != "nodeB" {
		t.Errorf("owner changed by stale heartbeat: %q", node)
	}
	if ttl := mr.TTL("tunnel:abc"); ttl > ttlBefore {
		t.Error("stale heartbeat must not refresh TTL")
	}
}

func TestBindRouteIfAbsentOrOwner_TwoState(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeA", "conn1"); err != nil || res != SelfHealBound {
		t.Fatalf("absent → bound: res=%v err=%v", res, err)
	}
	mr.HSet("tunnel:abc", "bytes_in", "7")
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeA", "conn1"); err != nil || res != SelfHealBound {
		t.Fatalf("same connID → bound: res=%v err=%v", res, err)
	}
	if got := mr.HGet("tunnel:abc", "bytes_in"); got != "7" {
		t.Errorf("a same-connID self-heal must keep the live byte counters, bytes_in=%q", got)
	}
	if res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeB", "conn2"); err != nil || res != SelfHealNotOwner {
		t.Fatalf("different connID → not-owner: res=%v err=%v", res, err)
	}
	if node, _, _, err := reg.LookupRoute(ctx, "abc"); err != nil {
		t.Fatal(err)
	} else if node != "nodeA" {
		t.Errorf("a not-owner self-heal must not clobber the route: node=%q", node)
	}
}

func TestHeartbeatDistinguishesMissingFromNotOwner(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if res, err := reg.Heartbeat(ctx, "gone", "conn1"); err != nil {
		t.Fatal(err)
	} else if res != HeartbeatMissing {
		t.Errorf("missing route heartbeat = %v, want HeartbeatMissing", res)
	}
	if err := reg.BindRoute(ctx, "abc", "nodeA", "conn2"); err != nil {
		t.Fatal(err)
	}
	if res, err := reg.Heartbeat(ctx, "abc", "conn1"); err != nil {
		t.Fatal(err)
	} else if res != HeartbeatNotOwner {
		t.Errorf("other-owner heartbeat = %v, want HeartbeatNotOwner", res)
	}
}
