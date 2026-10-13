package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testNode = "0a1b2c3d4e5f6a7b"

var t0 = time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeClock struct{ ns atomic.Int64 }

func newClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.ns.Store(t.UnixNano())
	return c
}

func (c *fakeClock) now() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) add(d time.Duration) { c.ns.Add(int64(d)) }
func (c *fakeClock) set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func (c *fakeClock) option() spoolOption { return withSpoolClock(c.now) }
func fastTicks() []spoolOption {
	return []spoolOption{withSpoolTick(time.Millisecond), withSpoolRetry(20 * time.Millisecond)}
}
func ev(tunnel string, i int) Event {
	return Event{Schema: 1, Event: "start", Tunnel: tunnel, SrcPort: i}
}

type upload struct {
	key  string
	body []byte
}

type fakeUploader struct {
	mu        sync.Mutex
	uploads   []upload
	failN     int
	block     bool
	gate      chan struct{}
	deadlines []time.Time
	ended     []error
}

func (f *fakeUploader) PutConnLogFile(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	if dl, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, dl)
	}
	if f.block {
		f.mu.Unlock()
		<-ctx.Done()
		f.mu.Lock()
		f.ended = append(f.ended, ctx.Err())
		f.mu.Unlock()
		return ctx.Err()
	}
	if f.failN > 0 {
		f.failN--
		f.mu.Unlock()
		return errors.New("s3 unavailable")
	}
	f.mu.Unlock()
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(raw)) != size {
		return errors.New("size mismatch")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads = append(f.uploads, upload{key: key, body: raw})
	return nil
}

func (f *fakeUploader) snapshot() []upload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upload(nil), f.uploads...)
}

type spoolEnv struct {
	s     *ConnLogSpool
	dir   string
	drops *atomic.Int64
	log   *syncBuf
}

func newSpool(t *testing.T, dir string, up ConnLogUploader, opts ...spoolOption) spoolEnv {
	t.Helper()
	drops := &atomic.Int64{}
	log := &syncBuf{}
	s, err := NewConnLogSpool(dir, testNode, up, func(n int) { drops.Add(int64(n)) },
		slog.New(slog.NewTextHandler(log, nil)), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drainWithin(s, 5*time.Second) })
	return spoolEnv{s: s, dir: dir, drops: drops, log: log}
}

func drainWithin(s *ConnLogSpool, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	s.Drain(ctx)
}

func put(t *testing.T, s *ConnLogSpool, evs ...Event) {
	t.Helper()
	for _, e := range evs {
		if err := s.PutConnLog(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func spoolFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if spoolName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func lines(t *testing.T, body []byte) []Event {
	t.Helper()
	var out []Event
	for _, l := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var e Event
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatalf("invalid JSONL line %q: %v", l, err)
		}
		out = append(out, e)
	}
	return out
}

func lineSize(t *testing.T, e Event) int64 {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(raw) + 1)
}

func seed(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSpool_WindowRotationUploadsAndDeletes(t *testing.T) {
	t.Parallel()
	clock := newClock(t0)
	up := &fakeUploader{}
	env := newSpool(t, t.TempDir(), up, append(fastTicks(), clock.option())...)
	put(t, env.s, ev("a", 1), ev("b", 2))
	want := lineSize(t, ev("a", 1)) + lineSize(t, ev("b", 2))
	waitFor(t, "both lines written", func() bool { return env.s.spooled.Load() == want })
	if got := up.snapshot(); len(got) != 0 {
		t.Fatalf("a file must not be uploaded before its window ends, got %d uploads", len(got))
	}
	clock.set(time.Date(2026, 10, 13, 10, 5, 0, 0, time.UTC))
	waitFor(t, "the upload", func() bool { return len(up.snapshot()) == 1 })
	u := up.snapshot()[0]
	if want := "tunnel-logs/2026/10/13/20261013T100200.000000000Z-" + testNode + ".jsonl"; u.key != want {
		t.Fatalf("key = %q, want %q", u.key, want)
	}
	if evs := lines(t, u.body); len(evs) != 2 || evs[0].Tunnel != "a" || evs[1].Tunnel != "b" {
		t.Fatalf("the object must carry both tunnels' events in order, got %+v", evs)
	}
	waitFor(t, "the local delete", func() bool { return len(spoolFiles(t, env.dir)) == 0 })
}

func TestSpool_SizeRotationNamesEachFileByItsStart(t *testing.T) {
	t.Parallel()
	clock := newClock(t0)
	up := &fakeUploader{gate: make(chan struct{})}
	env := newSpool(t, t.TempDir(), up, append(fastTicks(), clock.option(), withSpoolLimits(150, 1<<20))...)
	var written int64
	for i := range 6 {
		put(t, env.s, ev("a", i))
		written += lineSize(t, ev("a", i))
		waitFor(t, "the append", func() bool { return env.s.spooled.Load() == written })
		clock.add(time.Millisecond)
	}
	close(up.gate)
	drainWithin(env.s, 5*time.Second)
	got := up.snapshot()
	if len(got) < 2 {
		t.Fatalf("a file over the size limit must rotate, got %d objects", len(got))
	}
	keys := map[string]bool{}
	events := 0
	for _, u := range got {
		if keys[u.key] {
			t.Fatalf("two files must never share a key, %q repeated", u.key)
		}
		keys[u.key] = true
		events += len(lines(t, u.body))
	}
	if events != 6 {
		t.Fatalf("every event must be uploaded exactly once, got %d", events)
	}
}

func TestSpoolKey_LayoutSortAndRejects(t *testing.T) {
	t.Parallel()
	name := "20261013T235959.123456789Z-" + testNode + ".jsonl"
	key, err := spoolKey(name)
	if err != nil || key != "tunnel-logs/2026/10/13/"+name {
		t.Fatalf("spoolKey = (%q, %v)", key, err)
	}
	later := "20261013T235959.123456790Z-" + testNode + ".jsonl"
	if name >= later {
		t.Fatal("names must sort chronologically")
	}
	for _, bad := range []string{name + ".part", "notes.txt", ".lock", "20261013T999999.123456789Z-ab.jsonl"} {
		if _, err := spoolKey(bad); err == nil {
			t.Fatalf("spoolKey(%q) must fail", bad)
		}
	}
}

func TestSpool_NoEmptyFiles(t *testing.T) {
	t.Parallel()
	up := &fakeUploader{}
	env := newSpool(t, t.TempDir(), up, fastTicks()...)
	drainWithin(env.s, 5*time.Second)
	if files := spoolFiles(t, env.dir); len(files) != 0 || len(up.snapshot()) != 0 {
		t.Fatalf("no event must mean no file and no upload, files=%v uploads=%d", files, len(up.snapshot()))
	}
}

func TestSpool_ExistingNameAdvancesOneNanosecond(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	taken := t0.Format(tsNanosLayout) + "-" + testNode + ".jsonl"
	seed(t, dir, taken, `{"schema":1}`+"\n")
	clock := newClock(t0)
	env := newSpool(t, dir, &fakeUploader{block: true}, append(fastTicks(), clock.option())...)
	put(t, env.s, ev("a", 1))
	want := t0.Add(time.Nanosecond).Format(tsNanosLayout) + "-" + testNode + ".jsonl.part"
	waitFor(t, "the advanced name", func() bool {
		_, err := os.Stat(filepath.Join(dir, want))
		return err == nil
	})
	if raw, err := os.ReadFile(filepath.Join(dir, taken)); err != nil || string(raw) != `{"schema":1}`+"\n" {
		t.Fatalf("an existing ready file must never be overwritten: %q %v", raw, err)
	}
	drainWithin(env.s, 100*time.Millisecond)
}

func TestSpool_UploadsOldestFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var names []string
	for _, ts := range []string{"20261013T100500.000000000Z", "20261013T100000.000000000Z", "20261013T101000.000000000Z"} {
		n := ts + "-" + testNode + ".jsonl"
		seed(t, dir, n, `{"schema":1}`+"\n")
		names = append(names, n)
	}
	sort.Strings(names)
	up := &fakeUploader{}
	newSpool(t, dir, up, fastTicks()...)
	waitFor(t, "every leftover upload", func() bool { return len(up.snapshot()) == 3 })
	for i, u := range up.snapshot() {
		if !strings.HasSuffix(u.key, names[i]) {
			t.Fatalf("upload %d = %q, want oldest-first %q", i, u.key, names[i])
		}
	}
}

func TestSpool_FailedUploadKeptRetriedAndLogged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	name := "20261013T100000.000000000Z-" + testNode + ".jsonl"
	seed(t, dir, name, `{"schema":1}`+"\n")
	up := &fakeUploader{failN: 1}
	env := newSpool(t, dir, up, fastTicks()...)
	waitFor(t, "the retried upload", func() bool { return len(up.snapshot()) == 1 })
	waitFor(t, "the local delete", func() bool { return len(spoolFiles(t, dir)) == 0 })
	if !strings.Contains(env.log.String(), `msg="conn-log upload failed (will retry)"`) ||
		!strings.Contains(env.log.String(), name) || !strings.Contains(env.log.String(), "s3 unavailable") {
		t.Fatalf("the failed upload must be logged with the file and the error; log = %q", env.log.String())
	}
}

func TestSpool_UnreadableFileDoesNotBlockNewer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	older := seed(t, dir, "20261013T100000.000000000Z-"+testNode+".jsonl", `{"schema":1}`+"\n")
	if err := os.Chmod(older, 0o000); err != nil {
		t.Fatal(err)
	}
	newer := "20261013T100500.000000000Z-" + testNode + ".jsonl"
	seed(t, dir, newer, `{"schema":1}`+"\n")
	up := &fakeUploader{}
	env := newSpool(t, dir, up, fastTicks()...)
	waitFor(t, "the newer upload", func() bool { return len(up.snapshot()) == 1 })
	if !strings.HasSuffix(up.snapshot()[0].key, newer) {
		t.Fatalf("the readable newer file must still upload, got %q", up.snapshot()[0].key)
	}
	if !strings.Contains(env.log.String(), `msg="conn-log spool I/O failed" op=open`) {
		t.Fatalf("the unreadable file must be logged; log = %q", env.log.String())
	}
	if err := os.Chmod(older, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSpool_CapDropsWithOneWarnPerWindow(t *testing.T) {
	t.Parallel()
	clock := newClock(t0)
	env := newSpool(t, t.TempDir(), &fakeUploader{block: true}, append(fastTicks(), clock.option(), withSpoolLimits(1<<20, 200))...)
	var fit, fitBytes int64
	for i := range 20 {
		put(t, env.s, ev("a", i))
		if n := lineSize(t, ev("a", i)); fit == int64(i) && fitBytes+n <= 200 {
			fit, fitBytes = fit+1, fitBytes+n
		}
	}
	waitFor(t, "every event appended or dropped", func() bool {
		return env.s.spooled.Load() == fitBytes && env.drops.Load() == 20-fit
	})
	drainWithin(env.s, 100*time.Millisecond)
	if kept := int64(len(lines(t, mustRead(t, env.dir)))); fit == 20 || kept != fit {
		t.Fatalf("events past the cap must be dropped and counted, fit=%d kept=%d drops=%d", fit, kept, env.drops.Load())
	}
	if n := strings.Count(env.log.String(), "conn-log spool full"); n != 1 {
		t.Fatalf("the cap must be logged once per window, got %d", n)
	}
}

func mustRead(t *testing.T, dir string) []byte {
	t.Helper()
	files := spoolFiles(t, dir)
	if len(files) != 1 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSpool_ChannelFullDropsNewest(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	write := func(f *os.File, b []byte) (int, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return f.Write(b)
	}
	env := newSpool(t, t.TempDir(), &fakeUploader{}, append(fastTicks(),
		withFileOps(write, (*os.File).Sync, (*os.File).Truncate))...)
	put(t, env.s, ev("a", 0))
	<-entered
	for i := range spoolQueue + 10 {
		put(t, env.s, ev("a", i))
	}
	if got := env.drops.Load(); got != 10 {
		t.Fatalf("a full channel must drop exactly the overflow, drops = %d", got)
	}
	close(release)
}

func TestSpool_EventAfterDrainRefusedAndCounted(t *testing.T) {
	t.Parallel()
	env := newSpool(t, t.TempDir(), &fakeUploader{}, fastTicks()...)
	drainWithin(env.s, 5*time.Second)
	put(t, env.s, ev("a", 1))
	if env.drops.Load() != 1 {
		t.Fatalf("a post-shutdown event must be refused and counted, drops = %d", env.drops.Load())
	}
}

func TestSpool_RecoversTornAndEmptyPartFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	torn := "20261013T100000.000000000Z-ffffffffffffffff.jsonl"
	seed(t, dir, torn+".part", `{"schema":1,"tunnel":"a"}`+"\n"+`{"schema":1,"tun`)
	seed(t, dir, "20261013T100500.000000000Z-ffffffffffffffff.jsonl.part", `{"partial`)
	up := &fakeUploader{}
	env := newSpool(t, dir, up, fastTicks()...)
	waitFor(t, "the recovered upload", func() bool { return len(up.snapshot()) == 1 })
	u := up.snapshot()[0]
	if !strings.HasSuffix(u.key, torn) || string(u.body) != `{"schema":1,"tunnel":"a"}`+"\n" {
		t.Fatalf("the torn file must be truncated to its last newline, got %q %q", u.key, u.body)
	}
	if !strings.Contains(env.log.String(), `msg="conn-log spool recovered a torn last line (dropped)"`) {
		t.Fatalf("the dropped bytes must be logged; log = %q", env.log.String())
	}
	waitFor(t, "an empty spool", func() bool { return len(spoolFiles(t, dir)) == 0 })
}

func TestSpool_IgnoresNonSpoolEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seed(t, dir, "notes.txt", "keep me")
	if err := os.Mkdir(filepath.Join(dir, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	up := &fakeUploader{}
	env := newSpool(t, dir, up, fastTicks()...)
	drainWithin(env.s, 5*time.Second)
	if len(up.snapshot()) != 0 || env.s.spooled.Load() != 0 {
		t.Fatalf("non-spool entries must be ignored, uploads=%d spooled=%d", len(up.snapshot()), env.s.spooled.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("a non-spool file must be left alone: %v", err)
	}
}

func TestSpool_ShutdownRotatesUploadsAndReleasesLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	up := &fakeUploader{}
	env := newSpool(t, dir, up, fastTicks()...)
	put(t, env.s, ev("a", 1), ev("a", 2))
	drainWithin(env.s, 5*time.Second)
	if got := up.snapshot(); len(got) != 1 || len(lines(t, got[0].body)) != 2 {
		t.Fatalf("shutdown must rotate and upload the active file, got %+v", got)
	}
	if files := spoolFiles(t, dir); len(files) != 0 {
		t.Fatalf("an uploaded file must be deleted, left %v", files)
	}
	again := newSpool(t, dir, &fakeUploader{}, fastTicks()...)
	drainWithin(again.s, 5*time.Second)
}

func TestSpool_ShutdownPastDeadlineKeepsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	up := &fakeUploader{block: true}
	env := newSpool(t, dir, up, fastTicks()...)
	put(t, env.s, ev("a", 1))
	waitFor(t, "the append", func() bool { return env.s.spooled.Load() == lineSize(t, ev("a", 1)) })
	drainWithin(env.s, 100*time.Millisecond)
	up.mu.Lock()
	ended := append([]error(nil), up.ended...)
	up.mu.Unlock()
	if len(ended) == 0 || !errors.Is(ended[len(ended)-1], context.Canceled) {
		t.Fatalf("the drain deadline must cancel the in-flight upload, upload ends = %v", ended)
	}
	if files := spoolFiles(t, dir); len(files) != 1 || !strings.HasSuffix(files[0], spoolReadySuffix) {
		t.Fatalf("an un-uploaded file must stay on disk for the next start, got %v", files)
	}
	if !strings.Contains(env.log.String(), `msg="conn-log spool files left for the next start"`) {
		t.Fatalf("the leftover must be logged; log = %q", env.log.String())
	}
}

func TestSpool_HeldLockFailsFast(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := newSpool(t, dir, &fakeUploader{}, fastTicks()...)
	_, err := NewConnLogSpool(dir, testNode, &fakeUploader{}, func(int) {}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err == nil || !strings.Contains(err.Error(), "in use by another process") {
		t.Fatalf("a second spool on a locked directory must fail fast, got %v", err)
	}
	drainWithin(first.s, 5*time.Second)
	second := newSpool(t, dir, &fakeUploader{}, fastTicks()...)
	drainWithin(second.s, 5*time.Second)
}

func TestSpool_CreatesMissingDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "a", "spool")
	newSpool(t, dir, &fakeUploader{}, fastTicks()...)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the spool directory must be created 0700, got %v %v", fi, err)
	}
}

func TestSpool_ShortAppendRepaired(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	write := func(f *os.File, b []byte) (int, error) {
		if calls.Add(1) == 2 {
			n, err := f.Write(b[:len(b)/2])
			if err != nil {
				return n, err
			}
			return n, errors.New("no space left on device")
		}
		return f.Write(b)
	}
	up := &fakeUploader{}
	env := newSpool(t, t.TempDir(), up, append(fastTicks(), withFileOps(write, (*os.File).Sync, (*os.File).Truncate))...)
	put(t, env.s, ev("a", 1), ev("a", 2), ev("a", 3))
	drainWithin(env.s, 5*time.Second)
	got := up.snapshot()
	if len(got) != 1 {
		t.Fatalf("one object expected, got %d", len(got))
	}
	if evs := lines(t, got[0].body); len(evs) != 2 || evs[0].SrcPort != 1 || evs[1].SrcPort != 3 {
		t.Fatalf("the short append must be truncated away and the next line stay intact, got %+v", evs)
	}
	if env.drops.Load() != 1 {
		t.Fatalf("the failed append must be counted, drops = %d", env.drops.Load())
	}
}

func TestSpool_UnrepairableAppendRotates(t *testing.T) {
	t.Parallel()
	clock := newClock(t0)
	var calls atomic.Int32
	write := func(f *os.File, b []byte) (int, error) {
		if calls.Add(1) == 2 {
			return 0, errors.New("io error")
		}
		return f.Write(b)
	}
	truncate := func(*os.File, int64) error { return errors.New("truncate failed") }
	up := &fakeUploader{}
	env := newSpool(t, t.TempDir(), up, append(fastTicks(), clock.option(), withFileOps(write, (*os.File).Sync, truncate))...)
	put(t, env.s, ev("a", 1), ev("a", 2))
	waitFor(t, "the rotated file", func() bool { return len(up.snapshot()) == 1 })
	clock.add(time.Millisecond)
	put(t, env.s, ev("a", 3))
	drainWithin(env.s, 5*time.Second)
	if got := up.snapshot(); len(got) != 2 || got[0].key == got[1].key {
		t.Fatalf("an unrepairable append must rotate to a new file, got %+v", got)
	}
}

func TestSpool_FailedFsyncStillRotatesAndUploads(t *testing.T) {
	t.Parallel()
	failSync := func(*os.File) error { return errors.New("fsync failed") }
	up := &fakeUploader{}
	env := newSpool(t, t.TempDir(), up, append(fastTicks(), withFileOps((*os.File).Write, failSync, (*os.File).Truncate))...)
	put(t, env.s, ev("a", 1))
	drainWithin(env.s, 5*time.Second)
	if len(up.snapshot()) != 1 {
		t.Fatalf("a failed fsync must still rotate and upload, got %d uploads", len(up.snapshot()))
	}
	if !strings.Contains(env.log.String(), `op=fsync`) {
		t.Fatalf("the fsync failure must be logged; log = %q", env.log.String())
	}
}

func TestNewConnLogSpool_RejectsInvalidInput(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	drop := func(int) {}
	tests := []struct {
		name string
		make func(dir string) (*ConnLogSpool, error)
	}{
		{name: "empty dir", make: func(string) (*ConnLogSpool, error) {
			return NewConnLogSpool("", testNode, &fakeUploader{}, drop, logger)
		}},
		{name: "non-hex node id", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, "Node-1", &fakeUploader{}, drop, logger)
		}},
		{name: "nil uploader", make: func(d string) (*ConnLogSpool, error) { return NewConnLogSpool(d, testNode, nil, drop, logger) }},
		{name: "nil drop counter", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, nil, logger)
		}},
		{name: "nil logger", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, drop, nil)
		}},
		{name: "zero tick", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, drop, logger, withSpoolTick(0))
		}},
		{name: "zero retry", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, drop, logger, withSpoolRetry(0))
		}},
		{name: "zero limits", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, drop, logger, withSpoolLimits(0, 1))
		}},
		{name: "nil clock", make: func(d string) (*ConnLogSpool, error) {
			return NewConnLogSpool(d, testNode, &fakeUploader{}, drop, logger, withSpoolClock(nil))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if s, err := tc.make(t.TempDir()); err == nil || s != nil {
				t.Fatalf("NewConnLogSpool = (%v, %v), want a refusal", s, err)
			}
		})
	}
}

func TestSpool_DrainDeadlineDropsQueuedEventsAndStopsWriter(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	write := func(f *os.File, b []byte) (int, error) {
		select {
		case entered <- struct{}{}:
			<-release
		default:
		}
		return f.Write(b)
	}
	env := newSpool(t, t.TempDir(), &fakeUploader{}, append(fastTicks(), withFileOps(write, (*os.File).Sync, (*os.File).Truncate))...)
	put(t, env.s, ev("a", 0))
	<-entered
	put(t, env.s, ev("a", 1), ev("a", 2), ev("a", 3), ev("a", 4))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { env.s.Drain(ctx); close(done) }()
	waitFor(t, "the deadline to abandon the queue", env.s.abandon.Load)
	close(release)
	<-done
	select {
	case <-env.s.writerDone:
	default:
		t.Fatal("Drain must not return before the writer has stopped")
	}
	if env.drops.Load() != 4 {
		t.Fatalf("events still queued at the deadline must be counted as dropped, drops = %d", env.drops.Load())
	}
	if !strings.Contains(env.log.String(), `msg="conn-log events dropped at the shutdown deadline"`) ||
		!strings.Contains(env.log.String(), "events=4") {
		t.Fatalf("the abandoned events must be logged with their count; log = %q", env.log.String())
	}
}

func TestSpool_SuppressedIOErrorsAreSummarised(t *testing.T) {
	t.Parallel()
	failSync := func(*os.File) error { return errors.New("fsync failed") }
	for _, viaDrain := range []bool{false, true} {
		clock := newClock(t0)
		env := newSpool(t, t.TempDir(), &fakeUploader{}, append(fastTicks(), clock.option(),
			withSpoolLimits(10, 1<<20), withFileOps((*os.File).Write, failSync, (*os.File).Truncate))...)
		put(t, env.s, ev("a", 1))
		waitFor(t, "the first fsync failure", func() bool { return strings.Contains(env.log.String(), "op=fsync") })
		clock.add(time.Millisecond)
		put(t, env.s, ev("a", 2))
		waitFor(t, "the suppressed failure", func() bool {
			env.s.ioMu.Lock()
			defer env.s.ioMu.Unlock()
			return env.s.ioSuppressed == 1
		})
		if viaDrain {
			drainWithin(env.s, 5*time.Second)
		} else {
			clock.add(spoolIOLogEvery)
		}
		waitFor(t, "the suppressed summary", func() bool {
			return strings.Contains(env.log.String(), `msg="conn-log spool I/O failures suppressed" count=1 last_op=fsync`)
		})
	}
}

func TestSpool_UploadDeadlineScalesWithFileSize(t *testing.T) {
	t.Parallel()
	if got := uploadTimeout(16 << 20); got != 158*time.Second {
		t.Fatalf("a 16 MiB file must get 30 s + 128 s, got %v", got)
	}
	dir := t.TempDir()
	seed(t, dir, "20261013T100000.000000000Z-"+testNode+".jsonl", strings.Repeat("x", 1<<20))
	up := &fakeUploader{}
	start := time.Now()
	newSpool(t, dir, up, fastTicks()...)
	waitFor(t, "the upload", func() bool { return len(up.snapshot()) == 1 })
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.deadlines) != 1 || up.deadlines[0].Sub(start) < 38*time.Second || time.Until(up.deadlines[0]) > 38*time.Second {
		t.Fatalf("a 1 MiB upload must get a 38 s deadline from its start, got %v (test start %v)", up.deadlines, start)
	}
}
