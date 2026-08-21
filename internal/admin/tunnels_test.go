package admin

import (
	"context"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

type fakeMeta struct {
	names            []string
	next             uint64
	meta             map[string]router.TunnelMetaInfo
	scanErr, metaErr error
}

func (f *fakeMeta) ScanTunnels(context.Context, uint64, int64) ([]string, uint64, error) {
	return f.names, f.next, f.scanErr
}

func (f *fakeMeta) TunnelMeta(context.Context, []string) (map[string]router.TunnelMetaInfo, error) {
	return f.meta, f.metaErr
}

type fakeWin struct {
	win map[string]limit.TunnelStat
	err error
}

func (f *fakeWin) TunnelWindows(context.Context, []string) (map[string]limit.TunnelStat, error) {
	return f.win, f.err
}

func TestTunnels_List(t *testing.T) {
	tn := NewTunnels(&fakeMeta{names: []string{"a", "b"}, next: 42}, &fakeWin{})
	names, next, err := tn.List(context.Background(), 0, 100)
	if err != nil || next != 42 || len(names) != 2 {
		t.Fatalf("List = (%v, %d, %v)", names, next, err)
	}
}

// TestTunnels_Stats_MergesLiveOnly: Stats includes only names with a live route (from TunnelMeta), merging
// in their windows; a name present only in the windows (no route) is omitted.
func TestTunnels_Stats_MergesLiveOnly(t *testing.T) {
	meta := &fakeMeta{meta: map[string]router.TunnelMetaInfo{
		"a": {Node: "node1", BytesIn: 100, BytesOut: 50},
	}}
	win := &fakeWin{win: map[string]limit.TunnelStat{
		"a":      {Conc: 3, BwIn: 10, DayIn: 1000, WeekIn: 5000},
		"orphan": {Conc: 1}, // windows-only (no live route) → must be omitted
	}}
	tn := NewTunnels(meta, win)
	stats, err := tn.Stats(context.Background(), []string{"a", "orphan"})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 {
		t.Fatalf("Stats must include live tunnels only, got %v", stats)
	}
	a := stats["a"]
	if a.Node != "node1" || a.BytesIn != 100 || a.BytesOut != 50 || a.Conc != 3 || a.BwIn != 10 || a.DayIn != 1000 || a.WeekIn != 5000 {
		t.Errorf("merged stats for a = %+v", a)
	}
	if _, ok := stats["orphan"]; ok {
		t.Error("a windows-only (no live route) name must be omitted")
	}
}
