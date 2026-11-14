package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		key    string
		want   time.Time
		wantOK bool
	}{
		{name: "a tunneld file name", key: "tunnel-logs/2026/11/12/20261112T125530.080167786Z-c8809dcef89970cb.jsonl", want: time.Date(2026, 11, 12, 12, 55, 30, 80167786, time.UTC), wantOK: true},
		{name: "no node part", key: "tunnel-logs/2026/11/12/20261112T125530.080167786Z.jsonl"},
		{name: "not a time", key: "tunnel-logs/2026/11/12/yesterday-c8809dcef89970cb.jsonl"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := fileStart(tc.key)
			if ok != tc.wantOK || !got.Equal(tc.want) {
				t.Fatalf("fileStart(%q) = %v, %v; want %v, %v", tc.key, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestDayPrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		from, to time.Time
		want     []string
	}{
		{name: "a window across UTC midnight", from: time.Date(2026, 11, 11, 23, 50, 0, 0, time.UTC), to: testNow, want: []string{"tunnel-logs/2026/11/11/", "tunnel-logs/2026/11/12/"}},
		{name: "a window inside one UTC day", from: time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC), to: testNow, want: []string{"tunnel-logs/2026/11/12/"}},
		{name: "days are UTC days whatever the zone", from: time.Date(2026, 11, 12, 0, 30, 0, 0, testZone), to: time.Date(2026, 11, 12, 13, 0, 0, 0, testZone), want: []string{"tunnel-logs/2026/11/11/", "tunnel-logs/2026/11/12/"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dayPrefixes(tc.from, tc.to); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("dayPrefixes = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAddressOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "an IPv4 address is its own key", addr: "192.0.2.7", want: "192.0.2.7"},
		{name: "an IPv6 address is keyed by its /64", addr: "2001:db8:1:2::5", want: "2001:db8:1:2::/64"},
		{name: "another address of the same /64 has the same key", addr: "2001:db8:1:2:ffff::1", want: "2001:db8:1:2::/64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := addressOf(netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Fatalf("addressOf(%s) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestJob_ScanCountsPublicStartsInTheWindow(t *testing.T) {
	t.Parallel()
	h := newHarness()
	from := testNow.Add(-window)
	end := publicStart("192.0.2.7", "t1", "f1", testNow.Add(-39*time.Minute))
	end.Event = "end"
	phone := publicStart("192.0.2.7", "t1", "f1", testNow.Add(-30*time.Minute))
	phone.Type = "phone"
	h.store.addLog(t, testNow.Add(-time.Hour),
		publicStart("192.0.2.7", "t1", "f1", testNow.Add(-50*time.Minute)),
		publicStart("192.0.2.7", "t2", "f2", testNow.Add(-40*time.Minute)),
		end, phone,
		publicStart("198.51.100.4", "t1", "", testNow.Add(-20*time.Minute)),
		publicStart("192.0.2.7", "t3", "f3", from.Add(-time.Minute)),
		publicStart("192.0.2.7", "t4", "f4", testNow.Add(time.Minute)),
	)
	h.store.addLog(t, testNow.Add(-30*time.Minute), publicStart("192.0.2.7", "t1", "f1", testNow.Add(-10*time.Minute)))
	usages, tl, err := h.job(t).scan(context.Background(), from, testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if tl != (tally{files: 2, connections: 4}) {
		t.Fatalf("tally = %+v", tl)
	}
	a := usages["192.0.2.7"]
	if a == nil || a.connections != 3 || !reflect.DeepEqual(a.tunnels, map[string]struct{}{"t1": {}, "t2": {}}) ||
		!reflect.DeepEqual(a.fingerprints, map[string]struct{}{"f1": {}, "f2": {}}) ||
		!a.first.Equal(testNow.Add(-50*time.Minute)) || !a.last.Equal(testNow.Add(-10*time.Minute)) {
		t.Fatalf("usage of 192.0.2.7 = %+v", a)
	}
	b := usages["198.51.100.4"]
	if b == nil || b.connections != 1 || len(b.fingerprints) != 0 || len(usages) != 2 {
		t.Fatalf("usages = %+v", usages)
	}
}

func TestJob_ScanMergesAnIPv6Slash64(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.addLog(t, testNow.Add(-time.Hour), publicStart("2001:db8:1:2::5", "t1", "f1", testNow.Add(-30*time.Minute)))
	h.store.addLog(t, testNow.Add(-2*time.Hour), publicStart("2001:db8:1:2::9", "t2", "f1", testNow.Add(-100*time.Minute)))
	usages, _, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	u := usages["2001:db8:1:2::/64"]
	if len(usages) != 1 || u == nil || u.connections != 2 || len(u.tunnels) != 2 ||
		u.lookup != netip.MustParseAddr("2001:db8:1:2::9") || !u.first.Equal(testNow.Add(-100*time.Minute)) {
		t.Fatalf("usages = %+v", usages)
	}
}

func TestJob_ScanSkipsLeftOutAddresses(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.addLog(t, testNow.Add(-time.Hour),
		publicStart("192.0.2.9", "t1", "", testNow.Add(-50*time.Minute)),
		publicStart("198.51.100.7", "t1", "", testNow.Add(-50*time.Minute)),
		publicStart("198.51.100.8", "t1", "", testNow.Add(-50*time.Minute)),
		publicStart("::ffff:192.0.2.10", "t1", "", testNow.Add(-50*time.Minute)),
	)
	usages, _, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t, "192.0.2.0/24", "198.51.100.7/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(usages) != 1 || usages["198.51.100.8"] == nil {
		t.Fatalf("usages = %+v, want only 198.51.100.8", usages)
	}
}

func TestJob_ScanReadsOnlyFilesOfTheWindow(t *testing.T) {
	t.Parallel()
	h := newHarness()
	from := testNow.Add(-window)
	tooOld := h.store.addLog(t, from.Add(-11*time.Minute), publicStart("192.0.2.7", "t1", "", from.Add(-6*time.Minute)))
	inMargin := h.store.addLog(t, from.Add(-9*time.Minute), publicStart("192.0.2.7", "t1", "", from.Add(time.Second)))
	future := h.store.addLog(t, testNow.Add(time.Minute), publicStart("192.0.2.7", "t1", "", testNow))
	usages, tl, err := h.job(t).scan(context.Background(), from, testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if h.store.read(tooOld) || h.store.read(future) || !h.store.read(inMargin) {
		t.Fatalf("reads = %v", h.store.gets)
	}
	if tl.files != 1 || usages["192.0.2.7"] == nil || usages["192.0.2.7"].connections != 1 {
		t.Fatalf("tally %+v, usages %+v", tl, usages)
	}
}

func TestJob_ScanBadNamesAndLines(t *testing.T) {
	t.Parallel()
	h := newHarness()
	badName := "tunnel-logs/2026/11/12/garbage.jsonl"
	h.store.objects[badName] = []byte("{}\n")
	good, err := jsonLine(publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	badIP, err := jsonLine(publicStart("not-an-ip", "t1", "", testNow.Add(-time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	key := logKey(testNow.Add(-5*time.Minute), "0123456789abcdef")
	noTime, err := jsonLine(publicStart("192.0.2.7", "t1", "", time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	noTunnel, err := jsonLine(publicStart("192.0.2.7", "", "", testNow.Add(-time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	h.store.objects[key] = []byte("not json\n\n{}\nnull\n" + `{"event":"open","type":"public"}` + "\n" + `{"event":"start","type":"relay"}` + "\n" +
		badIP + "\n" + noTime + "\n" + noTunnel + "\n" + good + "\n")
	usages, tl, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if h.store.read(badName) || tl.malformed != 8 || tl.connections != 1 || usages["192.0.2.7"] == nil || len(usages["192.0.2.7"].tunnels) != 1 {
		t.Fatalf("tally %+v, usages %+v, reads %v", tl, usages, h.store.gets)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `level=WARN msg="a connection log has a name that does not start with its time`) || !strings.Contains(logs, badName) ||
		!strings.Contains(logs, `level=WARN msg="a connection log has lines that are not connection events`) || !strings.Contains(logs, "lines=8") {
		t.Fatalf("logs = %s", logs)
	}
}

func TestJob_ScanFailures(t *testing.T) {
	t.Parallel()
	key := logKey(testNow.Add(-time.Hour), "0123456789abcdef")
	tests := []struct {
		name     string
		setup    func(h *harness)
		wantErr  string
		wantLogs []string
	}{
		{name: "the listing fails", setup: func(h *harness) { h.store.listErr = errors.New("listing broke") }, wantErr: "list the connection logs under tunnel-logs/2026/11/11/: listing broke"},
		{name: "a read fails", setup: func(h *harness) { h.store.getErr[key] = errors.New("read broke") }, wantErr: "read the connection log " + key + ": read broke"},
		{name: "a read panics", setup: func(h *harness) {
			h.store.getHook = func(context.Context, string) error { panic("boom") }
		}, wantErr: "reading the connection log " + key + " crashed", wantLogs: []string{"level=ERROR", `msg="` + crashedMsg + `"`, "key=" + key, "panic=boom"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			h.store.addLog(t, testNow.Add(-time.Hour), publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute)))
			tc.setup(h)
			_, _, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			for _, want := range tc.wantLogs {
				if !strings.Contains(h.logs.String(), want) {
					t.Fatalf("logs = %s, want %q in them", h.logs.String(), want)
				}
			}
		})
	}
}

func TestJob_ScanSkipsALogGoneSinceTheListing(t *testing.T) {
	t.Parallel()
	h := newHarness()
	gone := logKey(testNow.Add(-time.Hour), "fedcba9876543210")
	h.store.listed = []string{gone}
	h.store.addLog(t, testNow.Add(-2*time.Hour), publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute)))
	usages, tl, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if !h.store.read(gone) || tl.files != 2 || usages["192.0.2.7"] == nil {
		t.Fatalf("tally %+v, usages %+v", tl, usages)
	}
	if logs := h.logs.String(); !strings.Contains(logs, `level=WARN msg="a connection log listed for this run is no longer in the bucket`) || !strings.Contains(logs, gone) {
		t.Fatalf("logs = %s", logs)
	}
}

func TestJob_ScanStoppedByItsTimeLimit(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.addLog(t, testNow.Add(-time.Hour), publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute)))
	h.store.addLog(t, testNow.Add(-2*time.Hour), publicStart("192.0.2.8", "t1", "", testNow.Add(-90*time.Minute)))
	h.store.getHook = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := h.job(t).scan(ctx, testNow.Add(-window), testNow, emptySet(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the time limit", err)
	}
}

func TestJob_ScanLongLines(t *testing.T) {
	t.Parallel()
	long := publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute))
	long.SNI = strings.Repeat("a", 100<<10)
	longLine, err := jsonLine(long)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		line            string
		wantConnections int
		wantMalformed   int
		wantErr         bool
	}{
		{name: "a line above bufio's 64 KiB default is counted", line: longLine, wantConnections: 1},
		{name: "a line just under 1 MiB is read", line: strings.Repeat("x", maxLineBytes-1), wantMalformed: 1},
		{name: "a line of 1 MiB fails the run", line: strings.Repeat("x", maxLineBytes), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			key := logKey(testNow.Add(-time.Hour), "0123456789abcdef")
			h.store.objects[key] = []byte(tc.line + "\n")
			_, tl, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "read the lines of the connection log "+key) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || tl.connections != tc.wantConnections || tl.malformed != tc.wantMalformed {
				t.Fatalf("tally %+v, err %v", tl, err)
			}
		})
	}
}

func TestJob_ScanAnEarlierEventLaterInTheFile(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.addLog(t, testNow.Add(-time.Hour),
		publicStart("2001:db8:1:2::5", "t1", "", testNow.Add(-10*time.Minute)),
		publicStart("2001:db8:1:2::9", "t1", "", testNow.Add(-50*time.Minute)),
	)
	usages, _, err := h.job(t).scan(context.Background(), testNow.Add(-window), testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	u := usages["2001:db8:1:2::/64"]
	if u == nil || u.lookup != netip.MustParseAddr("2001:db8:1:2::9") || !u.first.Equal(testNow.Add(-50*time.Minute)) ||
		!u.last.Equal(testNow.Add(-10*time.Minute)) {
		t.Fatalf("usage = %+v", u)
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()
	early := &usage{address: "2001:db8:1:2::/64", lookup: netip.MustParseAddr("2001:db8:1:2::9"), connections: 2,
		tunnels: map[string]struct{}{"t1": {}}, fingerprints: map[string]struct{}{"f1": {}},
		first: testNow.Add(-5 * time.Hour), last: testNow.Add(-4 * time.Hour)}
	late := &usage{address: "2001:db8:1:2::/64", lookup: netip.MustParseAddr("2001:db8:1:2::5"), connections: 3,
		tunnels: map[string]struct{}{"t2": {}}, fingerprints: map[string]struct{}{"f2": {}},
		first: testNow.Add(-2 * time.Hour), last: testNow.Add(-time.Hour)}
	clone := func(u *usage) *usage {
		c := *u
		c.tunnels = maps.Clone(u.tunnels)
		c.fingerprints = maps.Clone(u.fingerprints)
		return &c
	}
	tests := []struct {
		name        string
		first, then *usage
	}{
		{name: "the earlier file merged first", first: early, then: late},
		{name: "the later file merged first", first: late, then: early},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			total := map[string]*usage{}
			merge(total, map[string]*usage{tc.first.address: clone(tc.first)})
			merge(total, map[string]*usage{tc.then.address: clone(tc.then)})
			u := total["2001:db8:1:2::/64"]
			if u.connections != 5 || !reflect.DeepEqual(u.tunnels, map[string]struct{}{"t1": {}, "t2": {}}) ||
				!reflect.DeepEqual(u.fingerprints, map[string]struct{}{"f1": {}, "f2": {}}) ||
				!u.first.Equal(early.first) || u.lookup != early.lookup || !u.last.Equal(late.last) {
				t.Fatalf("merged = %+v", u)
			}
		})
	}
}

func TestJob_ScanReportsARealReadErrorAmongCancelledReads(t *testing.T) {
	t.Parallel()
	h := newHarness()
	broken := h.store.addLog(t, testNow.Add(-time.Hour), publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Minute)))
	h.store.addLog(t, testNow.Add(-2*time.Hour), publicStart("192.0.2.8", "t1", "", testNow.Add(-90*time.Minute)))
	h.store.addLog(t, testNow.Add(-3*time.Hour), publicStart("192.0.2.9", "t1", "", testNow.Add(-150*time.Minute)))
	h.store.getErr[broken] = errors.New("read broke")
	h.store.getHook = func(ctx context.Context, key string) error {
		if key == broken {
			return nil
		}
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := h.job(t).scan(ctx, testNow.Add(-window), testNow, emptySet(t))
	if err == nil || !strings.Contains(err.Error(), "read broke") || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want only the real read error", err)
	}
}

func TestJob_ScanReadsUpToTheParallelLimitAtOnce(t *testing.T) {
	t.Parallel()
	h := newHarness()
	for i := range 3 * parallelReads {
		h.store.addLog(t, testNow.Add(-time.Duration(i+1)*time.Minute), publicStart("192.0.2.7", "t1", "", testNow.Add(-time.Duration(i+1)*time.Minute)))
	}
	var (
		mu       sync.Mutex
		inFlight int
		most     int
		release  = make(chan struct{})
		once     sync.Once
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.store.getHook = func(ctx context.Context, _ string) error {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		if inFlight == parallelReads {
			once.Do(func() { close(release) })
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("fewer than %d reads ran at once: %w", parallelReads, ctx.Err())
		}
	}
	usages, tl, err := h.job(t).scan(ctx, testNow.Add(-window), testNow, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if most != parallelReads || tl.files != 3*parallelReads || usages["192.0.2.7"].connections != 3*parallelReads {
		t.Fatalf("at most %d reads ran at once (want %d), tally %+v", most, parallelReads, tl)
	}
}
