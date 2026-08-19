package limit

import (
	"testing"
	"time"
)

func TestAcquireStreamCapsInFlight(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-c"
	for i := 0; i < 4; i++ {
		ok, err := lim.AcquireStream(ctx, name, 4)
		if err != nil || !ok {
			t.Fatalf("acquire %d: ok=%v err=%v", i+1, ok, err)
		}
	}
	if ok, err := lim.AcquireStream(ctx, name, 4); err != nil || ok {
		t.Fatalf("5th acquire must fail: ok=%v err=%v", ok, err)
	}
	if err := lim.ReleaseStream(ctx, name); err != nil { // free a slot
		t.Fatal(err)
	}
	if ok, err := lim.AcquireStream(ctx, name, 4); err != nil || !ok {
		t.Fatalf("acquire after release must succeed: ok=%v err=%v", ok, err)
	}
}

func TestReleaseStreamDeletesKeyAtZero(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-idem"
	if ok, err := lim.AcquireStream(ctx, name, 1); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if err := lim.ReleaseStream(ctx, name); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("conc:" + name) {
		t.Error("counter must be deleted at zero, not left behind")
	}
	// A fresh acquire against max=1 must still succeed (count is 0, not negative).
	if ok, err := lim.AcquireStream(ctx, name, 1); err != nil || !ok {
		t.Fatalf("re-acquire after release: ok=%v err=%v", ok, err)
	}
}
