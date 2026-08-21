package limit

import (
	"testing"
	"time"
)

func TestLimiter_AcquireStream_CapNeverBreached(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-c"
	for i := 0; i < 4; i++ {
		ok, err := lim.AcquireStream(ctx, name, "conn1", 4)
		if err != nil || !ok {
			t.Fatalf("acquire %d: ok=%v err=%v", i+1, ok, err)
		}
	}
	if ok, err := lim.AcquireStream(ctx, name, "conn1", 4); err != nil || ok {
		t.Fatalf("5th acquire must be denied (cap): ok=%v err=%v", ok, err)
	}
	if err := lim.ReleaseStream(ctx, name, "conn1"); err != nil { // free a slot
		t.Fatal(err)
	}
	if ok, err := lim.AcquireStream(ctx, name, "conn1", 4); err != nil || !ok {
		t.Fatalf("acquire after release must succeed: ok=%v err=%v", ok, err)
	}
}

func TestLimiter_AcquireStream_FreshConnIDResets(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-reset"
	for i := 0; i < 3; i++ { // conn1 fills the cap
		if ok, err := lim.AcquireStream(ctx, name, "conn1", 3); err != nil || !ok {
			t.Fatalf("conn1 acquire %d: ok=%v err=%v", i+1, ok, err)
		}
	}
	// A fresh connection (conn2) resets the counter at its first acquire — the prior count is discarded.
	if ok, err := lim.AcquireStream(ctx, name, "conn2", 3); err != nil || !ok {
		t.Fatalf("conn2 fresh acquire must reset and succeed: ok=%v err=%v", ok, err)
	}
	if got := mr.HGet("conc:"+name, "count"); got != "1" {
		t.Errorf("count after fresh-connID reset = %q, want 1", got)
	}
	if got := mr.HGet("conc:"+name, "connID"); got != "conn2" {
		t.Errorf("owner after reset = %q, want conn2", got)
	}
}

func TestLimiter_AcquireStream_SetsTTL(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-ttl"
	if ok, err := lim.AcquireStream(ctx, name, "conn1", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if ttl := mr.TTL("conc:" + name); ttl <= 0 {
		t.Errorf("conc TTL = %s, want > 0", ttl)
	}
}

func TestLimiter_ReleaseStream_StragglerNoOp(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-straggler"
	_, _ = lim.AcquireStream(ctx, name, "conn2", 5) // conn2 owns 2 slots
	_, _ = lim.AcquireStream(ctx, name, "conn2", 5)
	// A straggler release from the superseded conn1 must NOT decrement conn2's count.
	if err := lim.ReleaseStream(ctx, name, "conn1"); err != nil {
		t.Fatal(err)
	}
	if got := mr.HGet("conc:"+name, "count"); got != "2" {
		t.Errorf("count after straggler release = %q, want 2 (unchanged)", got)
	}
}

func TestLimiter_ReleaseStream_DeleteAtZero(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-idem"
	if ok, err := lim.AcquireStream(ctx, name, "conn1", 1); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if err := lim.ReleaseStream(ctx, name, "conn1"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("conc:" + name) {
		t.Error("counter must be deleted at zero, not left behind")
	}
	// A fresh acquire against max=1 must still succeed (count starts at 0, not negative).
	if ok, err := lim.AcquireStream(ctx, name, "conn1", 1); err != nil || !ok {
		t.Fatalf("re-acquire after release: ok=%v err=%v", ok, err)
	}
}
