package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

var (
	testSince = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	testNow   = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func capturedLog(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, buf), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type fakeStore struct {
	mu       sync.Mutex
	objects  map[string][]byte
	modified map[string]time.Time
	listErr  error
	getErr   map[string]error
	get      func(ctx context.Context, key string) error
	reads    []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, modified: map[string]time.Time{}, getErr: map[string]error{}}
}

func (f *fakeStore) ListObjects(_ context.Context, prefix string) ([]bucket.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	seen := map[string]bool{}
	for k := range f.objects {
		seen[k] = true
	}
	for k := range f.getErr {
		seen[k] = true
	}
	var objs []bucket.Object
	for k := range seen {
		if strings.HasPrefix(k, prefix) {
			objs = append(objs, bucket.Object{Key: k, LastModified: f.modified[k]})
		}
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key })
	return objs, nil
}

func (f *fakeStore) Get(ctx context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	f.reads = append(f.reads, key)
	hook := f.get
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, key); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErr[key]; err != nil {
		return nil, err
	}
	body, ok := f.objects[key]
	if !ok {
		return nil, bucket.ErrNotFound
	}
	return body, nil
}

func (f *fakeStore) putName(t *testing.T, name string, enrolled, written time.Time, ca string) {
	t.Helper()
	rec := store.NameRecord{Schema: 1, EnrolledAt: enrolled}
	if ca != "" {
		rec.SetCert(store.CertInfo{CA: ca, Serial: "01", NotBefore: enrolled, NotAfter: enrolled.Add(160 * time.Hour)})
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[namesPrefix+name] = body
	f.modified[namesPrefix+name] = written
}

func (f *fakeStore) readKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := append([]string(nil), f.reads...)
	sort.Strings(keys)
	return keys
}

type harness struct {
	store    *fakeStore
	textfile string
	logs     *bytes.Buffer
	job      *job
}

func newHarness(t *testing.T, opts ...jobOption) *harness {
	t.Helper()
	h := &harness{store: newFakeStore(), textfile: filepath.Join(t.TempDir(), "arc_registered_phones.prom"), logs: &bytes.Buffer{}}
	j, err := newJob(jobConfig{Store: h.store, EnrolledSince: testSince, Textfile: h.textfile, Logger: capturedLog(h.logs)},
		append([]jobOption{withClock(func() time.Time { return testNow })}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	h.job = j
	return h
}

func (h *harness) writeOldTextfile(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.textfile, []byte(metrics(99, testNow.Add(-time.Hour))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) assertTextfileGone(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(h.textfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the old dashboard file must be removed, stat = %v", err)
	}
}

func TestJob_Run_CountsCertifiedNamesEnrolledSinceTheDay(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "atday", testSince, testSince, "letsencrypt")
	h.store.putName(t, "later", testSince.Add(26*time.Hour), testSince.Add(26*time.Hour), "gts")
	h.store.putName(t, "expired", testSince.Add(time.Hour), testSince.Add(time.Hour), "zerossl")
	h.store.putName(t, "before", testSince.Add(-time.Nanosecond), testSince.Add(-time.Nanosecond), "letsencrypt")
	h.store.putName(t, "nocert", testSince.Add(time.Hour), testSince.Add(time.Hour), "")
	h.store.getErr[namesPrefix+"gone"] = bucket.ErrNotFound
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(3, testNow) {
		t.Fatalf("textfile = %q, %v, want %q", got, err, metrics(3, testNow))
	}
	if !strings.Contains(h.logs.String(), "counted the registered phones for the dashboard") ||
		!strings.Contains(h.logs.String(), "registered=3 names_listed=6 names_read=6 enrolled_since=2026-11-06") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_SkipsRecordsLastWrittenBeforeTheDayLessTheClockSkew(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "old", testSince.Add(-48*time.Hour), testSince.Add(-clockSkew-time.Nanosecond), "gts")
	h.store.putName(t, "edge", testSince.Add(-clockSkew), testSince.Add(-clockSkew), "gts")
	h.store.putName(t, "renewed", testSince.Add(-48*time.Hour), testSince.Add(time.Hour), "gts")
	h.store.putName(t, "unknown", testSince, time.Time{}, "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.store.readKeys(), ","); got != "names/edge,names/renewed,names/unknown" {
		t.Fatalf("records read = %s, want every record except the one last written before the margin", got)
	}
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(1, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
	if !strings.Contains(h.logs.String(), "registered=1 names_listed=4 names_read=3") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_AnEmptyRegistryCountsZero(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(0, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestJob_Run_AFailureRemovesTheDashboardFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, f *fakeStore)
		want    string
		wantLog string
	}{
		{name: "the list fails", setup: func(_ *testing.T, f *fakeStore) { f.listErr = errors.New("list down") }, want: "list the name registry: list down"},
		{name: "a read fails", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, testSince, "gts")
			f.getErr[namesPrefix+"bad"] = errors.New("read down")
		}, want: "read the name record names/bad: read down"},
		{name: "a record does not decode", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, testSince, "gts")
			f.objects[namesPrefix+"junk"] = []byte("{")
		}, want: "decode the name record names/junk"},
		{name: "a read panics", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, testSince, "gts")
			f.get = func(_ context.Context, key string) error {
				if key == namesPrefix+"ok" {
					panic("boom")
				}
				return nil
			}
		}, want: "reading the name record names/ok crashed", wantLog: "key=names/ok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tc.setup(t, h.store)
			h.writeOldTextfile(t)
			err := h.job.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want an error containing %q", err, tc.want)
			}
			h.assertTextfileGone(t)
			if !strings.Contains(h.logs.String(), tc.wantLog) {
				t.Fatalf("logs = %s, want %q", h.logs.String(), tc.wantLog)
			}
		})
	}
}

func TestJob_Run_ATimeLimitEndsTheCountAndSaysSo(t *testing.T) {
	t.Parallel()
	h := newHarness(t, withTimeout(20*time.Millisecond))
	h.store.putName(t, "slow", testSince, testSince, "gts")
	h.store.get = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the count did not finish within 20ms") {
		t.Fatalf("run = %v, want the time-limit error", err)
	}
	h.assertTextfileGone(t)
}

func TestJob_Run_ACancelledRunIsNotCalledATimeout(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "slow", testSince, testSince, "gts")
	ctx, cancel := context.WithCancel(context.Background())
	h.store.get = func(ctx context.Context, _ string) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	err := h.job.run(ctx)
	if err == nil || strings.Contains(err.Error(), "did not finish within") || !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %v, want a plain cancellation", err)
	}
}

func TestJob_Run_AnUnwritableDashboardFileFails(t *testing.T) {
	t.Parallel()
	j, err := newJob(jobConfig{Store: newFakeStore(), EnrolledSince: testSince,
		Textfile: filepath.Join(t.TempDir(), "missing", "arc_registered_phones.prom"), Logger: testLog()})
	if err != nil {
		t.Fatal(err)
	}
	err = j.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write the dashboard file") || errors.Is(err, errTextfileKept) {
		t.Fatalf("run = %v, want a write error with nothing left to remove", err)
	}
}

func TestJob_Run_AnUnremovableDashboardFileIsReported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "arc_registered_phones.prom")
	if err := os.MkdirAll(filepath.Join(path, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := newJob(jobConfig{Store: newFakeStore(), EnrolledSince: testSince, Textfile: path, Logger: testLog()})
	if err != nil {
		t.Fatal(err)
	}
	err = j.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write the dashboard file") || !errors.Is(err, errTextfileKept) {
		t.Fatalf("run = %v, want the write error and the failed removal", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("no temporary file may be left: %v, %v", entries, err)
	}
}

func TestJob_Run_ReadsUpToTheParallelLimitAtOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for i := range 3 * parallelReads {
		h.store.putName(t, fmt.Sprintf("n%02d", i), testSince, testSince, "gts")
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
	h.store.get = func(ctx context.Context, _ string) error {
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
	if err := h.job.run(ctx); err != nil {
		t.Fatal(err)
	}
	if most != parallelReads {
		t.Fatalf("at most %d reads ran at once, want %d", most, parallelReads)
	}
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(3*parallelReads, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestNewJob_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	valid := jobConfig{Store: newFakeStore(), EnrolledSince: testSince, Textfile: "/tmp/x.prom", Logger: testLog()}
	tests := []struct {
		name   string
		change func(*jobConfig)
		opts   []jobOption
		want   string
	}{
		{name: "no store", change: func(c *jobConfig) { c.Store = nil }, want: "the object store is missing"},
		{name: "no first day", change: func(c *jobConfig) { c.EnrolledSince = time.Time{} }, want: "the first counted day is missing"},
		{name: "no textfile", change: func(c *jobConfig) { c.Textfile = "" }, want: "the dashboard file path is empty"},
		{name: "no logger", change: func(c *jobConfig) { c.Logger = nil }, want: "the logger is missing"},
		{name: "no clock", change: func(*jobConfig) {}, opts: []jobOption{withClock(nil)}, want: "the clock is missing"},
		{name: "no time limit", change: func(*jobConfig) {}, opts: []jobOption{withTimeout(0)}, want: "the time limit 0s is not positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := valid
			tc.change(&c)
			if _, err := newJob(c, tc.opts...); err == nil || err.Error() != tc.want {
				t.Fatalf("newJob = %v, want %q", err, tc.want)
			}
		})
	}
	j, err := newJob(valid)
	if err != nil {
		t.Fatalf("a complete config must be accepted: %v", err)
	}
	if j.timeout != defaultTimeout || j.now == nil {
		t.Fatalf("defaults = %s, clock set %v", j.timeout, j.now != nil)
	}
}
