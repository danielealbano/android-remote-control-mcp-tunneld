package limit

import (
	"strconv"
	"testing"
	"time"
)

func TestLimiter_TunnelWindows_ComputedKeys(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	base := time.Unix(1_700_000_000, 0)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	l.SetClock(func() time.Time { return base })
	const name = "t"
	sec := base.Unix()
	// conc:{name} is a HASH (AcquireStream writes {connID, count}) → read via HMGET, not the MGET.
	mr.HSet("conc:"+name, "connID", "c1", "count", "3")
	// The last-complete-second bandwidth + day/week windows are string counters.
	prev := strconv.FormatInt(sec-1, 10)
	d := strconv.FormatInt(sec/86400, 10)
	w := strconv.FormatInt(sec/86400/7, 10)
	for _, kv := range []struct{ k, v string }{
		{"bw:" + name + ":in:" + prev, "2048"},
		{"traf:" + name + ":in:day:" + d, "1000"},
		{"traf:" + name + ":out:week:" + w, "9000"},
	} {
		if err := mr.Set(kv.k, kv.v); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := l.TunnelWindows(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	s := stats[name]
	if s.Conc != 3 {
		t.Errorf("conc (read from the HASH via HMGET) = %d, want 3", s.Conc)
	}
	if s.BwIn != 2048 || s.DayIn != 1000 || s.WeekOut != 9000 {
		t.Errorf("windows = %+v", s)
	}
	// Empty names → empty map (no zero-key MGET).
	if got, err := l.TunnelWindows(ctx, nil); err != nil || len(got) != 0 {
		t.Errorf("empty names = %v err=%v", got, err)
	}
}

// TestLimiter_BwWindowTTL_Is3s: the per-second window TTL is 3s, so the last complete second stays
// readable by the admin bandwidth view.
func TestLimiter_BwWindowTTL_Is3s(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	base := time.Unix(1_700_000_000, 0)
	l := NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour)
	l.SetClock(func() time.Time { return base })
	if _, _, _, err := l.Charge(ctx, "t", "in", 1024); err != nil {
		t.Fatal(err)
	}
	bwKey, _, _, _ := chargeKeys("t", "in", base.Unix())
	if ttl := mr.TTL(bwKey); ttl <= 2*time.Second {
		t.Errorf("bw window TTL = %s, want 3s", ttl)
	}
}
