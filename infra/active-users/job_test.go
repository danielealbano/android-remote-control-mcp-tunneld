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
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

var testNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func capturedLog(buf *syncBuf) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, buf), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

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

type object struct {
	body []byte
	etag string
}

type fakeStore struct {
	mu      sync.Mutex
	objects map[string]object
	listErr error
	getErr  map[string]error
	get     func(ctx context.Context, key string)
	reads   []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string]object{}, getErr: map[string]error{}}
}

func (f *fakeStore) ListObjects(_ context.Context, prefix string) ([]bucket.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var objs []bucket.Object
	for k, o := range f.objects {
		if strings.HasPrefix(k, prefix) {
			objs = append(objs, bucket.Object{Key: k, ETag: o.etag})
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
		hook(ctx, key)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErr[key]; err != nil {
		return nil, err
	}
	o, ok := f.objects[key]
	if !ok {
		return nil, bucket.ErrNotFound
	}
	return o.body, nil
}

func (f *fakeStore) putList(t *testing.T, key, etag string, last map[string]time.Time) {
	t.Helper()
	pf := store.PhonesSeenFile{Schema: 1, Node: "0a1b", Day: "2026-11-26", Phones: map[string]store.PhoneSeen{}}
	for name, at := range last {
		pf.Phones[name] = store.PhoneSeen{First: at.Add(-time.Minute), Last: at}
	}
	body, err := json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = object{body: body, etag: etag}
}

func (f *fakeStore) takeReads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reads
	f.reads = nil
	sort.Strings(r)
	return r
}

type env struct {
	st       *fakeStore
	dir      string
	cache    string
	textfile string
	log      *syncBuf
}

func newEnv(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	return env{st: newFakeStore(), dir: dir, cache: filepath.Join(dir, "cache.json"), textfile: filepath.Join(dir, "arc_active_users.prom"), log: &syncBuf{}}
}

func (e env) run(t *testing.T, opts ...jobOption) error {
	t.Helper()
	j, err := newJob(jobConfig{Store: e.st, CacheFile: e.cache, Textfile: e.textfile, Logger: capturedLog(e.log)},
		append([]jobOption{withClock(func() time.Time { return testNow })}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return j.run(context.Background())
}

func (e env) counts(t *testing.T) string {
	t.Helper()
	got, err := os.ReadFile(e.textfile)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func wantCounts(dau, wau, mau int) string {
	return metrics(map[string]int{"24h": dau, "7d": wau, "30d": mau}, testNow)
}

func listKeyFor(day, node string) string {
	return store.PhonesSeenPrefix + day + "/" + node + ".json"
}

func TestJob_CountsEachUserOnceInEachRollingWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"today": testNow.Add(-time.Hour), "both": testNow.Add(-2 * time.Hour)})
	e.st.putList(t, listKeyFor("2026/11/26", "bb"), `"2"`, map[string]time.Time{"today": testNow.Add(-10 * time.Minute)})
	e.st.putList(t, listKeyFor("2026/11/25", "aa"), `"3"`, map[string]time.Time{"edge24": testNow.Add(-24*time.Hour + time.Second), "out24": testNow.Add(-24 * time.Hour), "both": testNow.Add(-26 * time.Hour)})
	e.st.putList(t, listKeyFor("2026/11/20", "cc"), `"4"`, map[string]time.Time{"week": testNow.Add(-6 * 24 * time.Hour)})
	e.st.putList(t, listKeyFor("2026/10/28", "dd"), `"5"`, map[string]time.Time{"month": testNow.Add(-29 * 24 * time.Hour), "out30": testNow.Add(-30 * 24 * time.Hour)})
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got, want := e.counts(t), wantCounts(3, 5, 6); got != want {
		t.Fatalf("textfile = %q, want %q (each user once, the window start excluded)", got, want)
	}
	if !strings.Contains(e.log.String(), `msg="counted the active users for the dashboard" dau=3 wau=5 mau=6 lists_listed=5 lists_read=5 lists_skipped=0`) {
		t.Fatalf("the count must be logged; log = %q", e.log.String())
	}
}

func TestJob_ReadsOnlyNewOrChangedListsAndForgetsRemovedOnes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := listKeyFor("2026/11/26", "aa"), listKeyFor("2026/11/25", "bb")
	e.st.putList(t, a, `"a1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
	e.st.putList(t, b, `"b1"`, map[string]time.Time{"y": testNow.Add(-30 * time.Hour)})
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got := e.st.takeReads(); !slices.Equal(got, []string{b, a}) {
		t.Fatalf("the first run must read every list, read %v", got)
	}
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got := e.st.takeReads(); len(got) != 0 {
		t.Fatalf("an unchanged list must come from the cache, read %v", got)
	}
	e.st.putList(t, a, `"a2"`, map[string]time.Time{"x": testNow.Add(-time.Hour), "z": testNow.Add(-time.Minute)})
	e.st.mu.Lock()
	delete(e.st.objects, b)
	e.st.mu.Unlock()
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got := e.st.takeReads(); !slices.Equal(got, []string{a}) {
		t.Fatalf("only the changed list may be read, read %v", got)
	}
	if got, want := e.counts(t), wantCounts(2, 2, 2); got != want {
		t.Fatalf("a list gone from the bucket must stop counting: textfile = %q, want %q", got, want)
	}
	raw, err := os.ReadFile(e.cache)
	if err != nil {
		t.Fatal(err)
	}
	var c cache
	if err := json.Unmarshal(raw, &c); err != nil || len(c.Lists) != 1 || c.Lists[a].ETag != `"a2"` {
		t.Fatalf("the cache must hold only the lists still in the bucket, got %s (%v)", raw, err)
	}
}

func TestJob_ListsWithoutAnETagAreAlwaysRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := listKeyFor("2026/11/26", "aa")
	e.st.putList(t, a, "", map[string]time.Time{"x": testNow.Add(-time.Hour)})
	for range 2 {
		if err := e.run(t); err != nil {
			t.Fatal(err)
		}
		if got := e.st.takeReads(); !slices.Equal(got, []string{a}) {
			t.Fatalf("a list without an ETag cannot be matched to the cache, so it must be read, read %v", got)
		}
	}
}

func TestJob_NeverReadsListsOlderThanTheLongestWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.st.putList(t, listKeyFor("2026/10/25", "aa"), `"old"`, map[string]time.Time{"gone": testNow.Add(-32 * 24 * time.Hour)})
	edge := listKeyFor("2026/10/26", "aa")
	e.st.putList(t, edge, `"edge"`, map[string]time.Time{"late": time.Date(2026, 10, 27, 0, 0, 30, 0, time.UTC)})
	in := listKeyFor("2026/10/27", "aa")
	e.st.putList(t, in, `"in"`, map[string]time.Time{"inside": testNow.Add(-30*24*time.Hour + time.Second)})
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got := e.st.takeReads(); !slices.Equal(got, []string{edge, in}) {
		t.Fatalf("only lists that can still hold a time in the last 30 days may be read, read %v", got)
	}
	if got, want := e.counts(t), wantCounts(0, 0, 1); got != want {
		t.Fatalf("textfile = %q, want %q", got, want)
	}
}

func TestJob_ABrokenCacheIsRebuiltFromTheBucket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		cache string
		want  string
	}{
		{name: "not JSON", cache: "{", want: `msg="could not decode this node's cache, so every list of phones seen is read from the bucket again"`},
		{name: "another format", cache: `{"schema":9,"lists":{}}`, want: `msg="this node's cache has another format, so every list of phones seen is read from the bucket again" cache_file=`},
		{name: "no lists", cache: `{"schema":1}`, want: `msg="this node's cache has another format, so every list of phones seen is read from the bucket again" cache_file=`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if err := os.WriteFile(e.cache, []byte(tc.cache), 0o600); err != nil {
				t.Fatal(err)
			}
			e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
			if err := e.run(t); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(e.log.String(), tc.want) {
				t.Fatalf("the broken cache must be logged; log = %q", e.log.String())
			}
			if got, want := e.counts(t), wantCounts(1, 1, 1); got != want {
				t.Fatalf("textfile = %q, want %q", got, want)
			}
		})
	}
}

func TestJob_AnUnreadableCacheIsRebuiltFromTheBucket(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := os.MkdirAll(e.cache, 0o700); err != nil {
		t.Fatal(err)
	}
	e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`level=WARN msg="could not read this node's cache, so every list of phones seen is read from the bucket again" cache_file=` + e.cache,
		`level=WARN msg="could not save this node's cache, so the next run reads the lists again" cache_file=` + e.cache,
	} {
		if !strings.Contains(e.log.String(), want) {
			t.Fatalf("log must contain %q; log = %q", want, e.log.String())
		}
	}
	if got, want := e.counts(t), wantCounts(1, 1, 1); got != want {
		t.Fatalf("textfile = %q, want %q", got, want)
	}
}

func TestJob_FirstRunSaysItHasNoCache(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log.String(), `level=INFO msg="this node has no cache yet, so every list of phones seen is read from the bucket"`) {
		t.Fatalf("the first run must say why it reads everything; log = %q", e.log.String())
	}
	if got, want := e.counts(t), wantCounts(0, 0, 0); got != want {
		t.Fatalf("no lists must count zero users: textfile = %q, want %q", got, want)
	}
}

func TestJob_SkipsWhatCannotBeCountedAndSaysSo(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	bad := listKeyFor("2026/11/26", "aa")
	e.st.mu.Lock()
	e.st.objects[bad] = object{body: []byte("{"), etag: `"bad"`}
	e.st.objects[store.PhonesSeenPrefix+"notes.txt"] = object{body: []byte("x"), etag: `"n"`}
	e.st.objects[store.PhonesSeenPrefix+"2026/13/40/aa.json"] = object{body: []byte("{}"), etag: `"d"`}
	e.st.mu.Unlock()
	gone := listKeyFor("2026/11/26", "bb")
	e.st.getErr[gone] = bucket.ErrNotFound
	e.st.putList(t, gone, `"g"`, nil)
	e.st.putList(t, listKeyFor("2026/11/26", "cc"), `"ok"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
	for range 2 {
		if err := e.run(t); err != nil {
			t.Fatal(err)
		}
	}
	log := e.log.String()
	for _, want := range []string{
		`level=WARN msg="could not decode a list of phones seen, so it is not counted; it is read again on the next run" key=` + bad,
		`level=WARN msg="found an object that is not a list of phones seen under the lists' folder, so it is not counted" key=` + store.PhonesSeenPrefix + "notes.txt",
		`level=WARN msg="found a list of phones seen whose folder is not a real day, so it is not counted" key=` + store.PhonesSeenPrefix + "2026/13/40/aa.json",
		`level=INFO msg="a list of phones seen was removed between listing and reading it, so it is not counted" key=` + gone,
		`lists_listed=5 lists_read=0 lists_skipped=4`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log must contain %q; log = %q", want, log)
		}
	}
	if got := strings.Count(log, `msg="could not decode a list of phones seen`); got != 2 {
		t.Fatalf("an undecodable list must not be cached, so each run warns again; warned %d times", got)
	}
	if got, want := e.counts(t), wantCounts(1, 1, 1); got != want {
		t.Fatalf("textfile = %q, want %q", got, want)
	}
}

func TestJob_FailsWithoutTouchingTheDashboardFileWhenTheBucketFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(e env)
		want  string
	}{
		{name: "list", setup: func(e env) { e.st.listErr = errors.New("list refused") }, want: "list the lists of phones seen: list refused"},
		{name: "read", setup: func(e env) {
			e.st.getErr[listKeyFor("2026/11/26", "aa")] = errors.New("read refused")
		}, want: "read the list of phones seen " + listKeyFor("2026/11/26", "aa") + ": read refused"},
		{name: "crash", setup: func(e env) {
			e.st.get = func(context.Context, string) { panic("boom") }
		}, want: "reading the list of phones seen " + listKeyFor("2026/11/26", "aa") + " crashed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
			tc.setup(e)
			err := e.run(t)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want %q", err, tc.want)
			}
			for _, p := range []string{e.textfile, e.cache} {
				if _, serr := os.Stat(p); !errors.Is(serr, os.ErrNotExist) {
					t.Fatalf("a failed run must write neither the dashboard file nor the cache, %s: %v", p, serr)
				}
			}
		})
	}
}

func TestJob_TimeoutNamesTheLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
	e.st.get = func(ctx context.Context, _ string) { <-ctx.Done() }
	err := e.run(t, withTimeout(20*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "the run did not finish within 20ms") {
		t.Fatalf("run = %v, want the time limit in the error", err)
	}
}

func TestJob_CacheThatCannotBeSavedStillUpdatesTheDashboard(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.st.putList(t, listKeyFor("2026/11/26", "aa"), `"1"`, map[string]time.Time{"x": testNow.Add(-time.Hour)})
	write := func(path string, data []byte, mode os.FileMode) error {
		if path == e.cache {
			return errors.New("disk full")
		}
		return atomicfile.Write(path, data, mode)
	}
	if err := e.run(t, withWriter(write)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log.String(), `level=WARN msg="could not save this node's cache, so the next run reads the lists again" cache_file=`+e.cache+` err="disk full"`) {
		t.Fatalf("the failed cache save must be logged; log = %q", e.log.String())
	}
	if got, want := e.counts(t), wantCounts(1, 1, 1); got != want {
		t.Fatalf("textfile = %q, want %q", got, want)
	}
}

func TestJob_DashboardFileErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     error
		wantErr string
		wantLog string
	}{
		{name: "not written", err: errors.New("read-only"), wantErr: "write the dashboard file: read-only"},
		{name: "written but not flushed", err: fmt.Errorf("%w: sync", atomicfile.ErrNotFlushed),
			wantLog: `level=WARN msg="wrote this node's dashboard file but could not flush it to disk, so a crash could lose it until the next run"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			write := func(path string, data []byte, mode os.FileMode) error {
				if path == e.textfile {
					return tc.err
				}
				return atomicfile.Write(path, data, mode)
			}
			err := e.run(t, withWriter(write))
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("run = %v, want %q", err, tc.wantErr)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("run = %v, want success", err)
			}
			if tc.wantLog != "" && !strings.Contains(e.log.String(), tc.wantLog) {
				t.Fatalf("log must contain %q; log = %q", tc.wantLog, e.log.String())
			}
		})
	}
}

func TestNewJob_RejectsMissingSettings(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	full := jobConfig{Store: newFakeStore(), CacheFile: "c", Textfile: "t", Logger: logger}
	tests := []struct {
		name string
		cfg  func(c jobConfig) jobConfig
		opts []jobOption
		want string
	}{
		{name: "store", cfg: func(c jobConfig) jobConfig { c.Store = nil; return c }, want: "the object store is missing"},
		{name: "cache file", cfg: func(c jobConfig) jobConfig { c.CacheFile = ""; return c }, want: "the cache file path is empty"},
		{name: "textfile", cfg: func(c jobConfig) jobConfig { c.Textfile = ""; return c }, want: "the dashboard file path is empty"},
		{name: "logger", cfg: func(c jobConfig) jobConfig { c.Logger = nil; return c }, want: "the logger is missing"},
		{name: "clock", cfg: func(c jobConfig) jobConfig { return c }, opts: []jobOption{withClock(nil)}, want: "the clock is missing"},
		{name: "writer", cfg: func(c jobConfig) jobConfig { return c }, opts: []jobOption{withWriter(nil)}, want: "the file writer is missing"},
		{name: "timeout", cfg: func(c jobConfig) jobConfig { return c }, opts: []jobOption{withTimeout(0)}, want: "the time limit 0s is not positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newJob(tc.cfg(full), tc.opts...); err == nil || err.Error() != tc.want {
				t.Fatalf("newJob = %v, want %q", err, tc.want)
			}
		})
	}
}
