package limit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestLimiter_AcquireStream_CapNeverBreached(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-c"
	for i := range 4 {
		ok, err := lim.AcquireStream(ctx, name, fmt.Sprintf("m%d", i), 4)
		if err != nil || !ok {
			t.Fatalf("acquire %d: ok=%v err=%v", i+1, ok, err)
		}
	}
	if ok, err := lim.AcquireStream(ctx, name, "m4", 4); err != nil || ok {
		t.Fatalf("5th acquire must be denied (cap): ok=%v err=%v", ok, err)
	}
	members, err := mr.ZMembers("conc:" + name)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 4 {
		t.Fatalf("set = %v, want exactly the 4 admitted members", members)
	}
	for _, m := range members {
		if m == "m4" {
			t.Fatal("a refused member must not be left in the set")
		}
	}
}

func TestLimiter_AcquireStream_ConcurrentNeverOverCap(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-race"
	var (
		mu       sync.Mutex
		admitted []string
		wg       sync.WaitGroup
	)
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			member := fmt.Sprintf("m%02d", i)
			ok, err := lim.AcquireStream(ctx, name, member, 4)
			if err != nil {
				t.Errorf("acquire %s: %v", member, err)
				return
			}
			if ok {
				mu.Lock()
				admitted = append(admitted, member)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(admitted) > 4 {
		t.Fatalf("admitted %d > cap 4: %v", len(admitted), admitted)
	}
	members, err := mr.ZMembers("conc:" + name)
	if err != nil && len(admitted) > 0 {
		t.Fatal(err)
	}
	sort.Strings(admitted)
	sort.Strings(members)
	if fmt.Sprint(members) != fmt.Sprint(admitted) {
		t.Fatalf("set = %v, want exactly the admitted members %v", members, admitted)
	}
}

func TestLimiter_AcquireStream_PrunesExpiredMembers(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	clk := time.Unix(1_700_000_000, 0)
	lim := NewLimiter(rdb, 0, 0, 0, time.Minute)
	lim.SetClock(func() time.Time { return clk })
	const name = "tunnel-prune"
	for i := range 2 {
		if ok, err := lim.AcquireStream(ctx, name, fmt.Sprintf("old%d", i), 2); err != nil || !ok {
			t.Fatalf("acquire %d: ok=%v err=%v", i, ok, err)
		}
	}
	if ok, err := lim.AcquireStream(ctx, name, "early", 2); err != nil || ok {
		t.Fatalf("a full set must refuse: ok=%v err=%v", ok, err)
	}
	clk = clk.Add(time.Minute + time.Millisecond)
	if ok, err := lim.AcquireStream(ctx, name, "new", 2); err != nil || !ok {
		t.Fatalf("an admission after the members expired must prune them and admit: ok=%v err=%v", ok, err)
	}
	members, err := mr.ZMembers("conc:" + name)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0] != "new" {
		t.Fatalf("set = %v, want only the new member", members)
	}
}

func TestLimiter_AcquireStream_SetsKeyTTLAndScore(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	clk := time.Unix(1_700_000_000, 0)
	const ttl = 45 * time.Minute
	lim := NewLimiter(rdb, 0, 0, 0, ttl)
	lim.SetClock(func() time.Time { return clk })
	if ok, err := lim.AcquireStream(ctx, "t", "m1", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if typ := mr.Type("conc:t"); typ != "zset" {
		t.Fatalf("conc:t type = %q, want zset", typ)
	}
	if got := mr.TTL("conc:t"); got != ttl {
		t.Errorf("conc:t TTL = %s, want %s", got, ttl)
	}
	score, err := mr.ZScore("conc:t", "m1")
	if err != nil {
		t.Fatal(err)
	}
	if want := float64(clk.Add(ttl).UnixMilli()); score != want {
		t.Errorf("member score = %v, want now+streamTTL in ms = %v", score, want)
	}
}

func TestLimiter_ReleaseStream_RemovesOnlyItsMember(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-rel"
	for _, m := range []string{"a", "b"} {
		if ok, err := lim.AcquireStream(ctx, name, m, 4); err != nil || !ok {
			t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
		}
	}
	if err := lim.ReleaseStream(ctx, name, "a"); err != nil {
		t.Fatal(err)
	}
	if err := lim.ReleaseStream(ctx, name, "unknown"); err != nil {
		t.Fatalf("releasing an unknown member must be a no-op: %v", err)
	}
	members, err := mr.ZMembers("conc:" + name)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0] != "b" {
		t.Fatalf("set = %v, want only b", members)
	}
}

func TestLimiter_ReleaseStream_DetachedAndBounded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		cancelledCaller bool
	}{
		{name: "caller without a deadline"},
		{name: "caller already cancelled", cancelledCaller: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rdb, mr := newTestRedis(t)
			lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
			const name = "tunnel-rel"
			for _, m := range []string{"a", "b"} {
				if ok, err := lim.AcquireStream(ctxT(t), name, m, 2); err != nil || !ok {
					t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rec := &deadlineRecorder{left: map[string]time.Duration{}}
			rdb.AddHook(rec)
			if tc.cancelledCaller {
				cancel()
			}
			if err := lim.ReleaseStream(ctx, name, "a"); err != nil {
				t.Fatalf("release: %v", err)
			}
			members, err := mr.ZMembers(concKey(name))
			if err != nil {
				t.Fatal(err)
			}
			if len(members) != 1 || members[0] != "b" {
				t.Fatalf("set = %v, want only b", members)
			}
			rec.mu.Lock()
			left, ok := rec.left["zrem"]
			rec.mu.Unlock()
			if !ok || left <= 0 || left > streamReleaseTimeout {
				t.Fatalf("the release ran with %s left (deadline set: %v), want its own (0, %s] bound", left, ok, streamReleaseTimeout)
			}
		})
	}
}

func TestLimiter_AcquireStream_RollbackSurvivesCancelledCaller(t *testing.T) {
	t.Parallel()
	rdb, mr := newTestRedis(t)
	lim := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "tunnel-rb"
	for _, m := range []string{"a", "b"} {
		if ok, err := lim.AcquireStream(ctxT(t), name, m, 2); err != nil || !ok {
			t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rdb.AddHook(tunneltest.CancelBefore("zrem", cancel))
	if ok, err := lim.AcquireStream(ctx, name, "c", 2); err != nil || ok {
		t.Fatalf("acquire over the cap = (%v, %v), want a plain refusal", ok, err)
	}
	members, err := mr.ZMembers(concKey(name))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(members)
	if len(members) != 2 || members[0] != "a" || members[1] != "b" {
		t.Fatalf("set = %v, want only a and b: the refused member must be rolled back although the caller was cancelled", members)
	}
}

func TestLimiter_AcquireStream_RollbackFailureLogged(t *testing.T) {
	t.Parallel()
	l, mr, rdb, buf := newLoggedLimiter(t)
	const name = "tunnel-rf"
	for _, m := range []string{"a", "b"} {
		if ok, err := l.AcquireStream(ctxT(t), name, m, 2); err != nil || !ok {
			t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
		}
	}
	rdb.AddHook(tunneltest.FailCommands(errInjected, "zrem"))
	if ok, err := l.AcquireStream(ctxT(t), name, "c", 2); err != nil || ok {
		t.Fatalf("acquire over the cap with a failing rollback = (%v, %v), want a plain refusal", ok, err)
	}
	if !strings.Contains(buf.String(), `msg="could not undo an open-connection slot; it expires on its own" tunnel=tunnel-rf`) {
		t.Fatalf("the failed rollback must be logged; log = %q", buf.String())
	}
	if score, err := mr.ZScore(concKey(name), "c"); err != nil || score <= 0 {
		t.Fatalf("the member whose rollback failed must remain until its score expires: score=%v err=%v", score, err)
	}
}
