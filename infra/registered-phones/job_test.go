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

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
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
	putErr   map[string]error
	get      func(ctx context.Context, key string) error
	reads    []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, modified: map[string]time.Time{}, getErr: map[string]error{}, putErr: map[string]error{}}
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	if strings.HasPrefix(key, namesPrefix) {
		f.reads = append(f.reads, key)
	}
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

func (f *fakeStore) Put(_ context.Context, key string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.putErr[key]; err != nil {
		return err
	}
	f.objects[key] = append([]byte(nil), body...)
	return nil
}

func (f *fakeStore) putName(t *testing.T, name string, enrolled, written time.Time, ca string) {
	t.Helper()
	f.putNameValidUntil(t, name, enrolled, written, ca, enrolled.Add(160*time.Hour))
}

func (f *fakeStore) putNameValidUntil(t *testing.T, name string, enrolled, written time.Time, ca string, notAfter time.Time) {
	t.Helper()
	rec := store.NameRecord{Schema: 1, EnrolledAt: enrolled}
	if ca != "" {
		rec.SetCert(store.CertInfo{CA: ca, Serial: "01", NotBefore: enrolled, NotAfter: notAfter})
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

func (f *fakeStore) putState(t *testing.T, s state) {
	t.Helper()
	body := mustJSON(t, s)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[stateKey] = body
}

func (f *fakeStore) stateBody() ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[stateKey]
	return body, ok
}

func (f *fakeStore) readKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := append([]string(nil), f.reads...)
	sort.Strings(keys)
	return keys
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type harness struct {
	store     *fakeStore
	textfile  string
	stateFile string
	logs      *bytes.Buffer
	job       *job
}

func newHarness(t *testing.T, opts ...jobOption) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{store: newFakeStore(), textfile: filepath.Join(dir, "arc_registered_phones.prom"),
		stateFile: filepath.Join(dir, "state.json"), logs: &bytes.Buffer{}}
	h.job = h.newJob(t, opts...)
	return h
}

func (h *harness) newJob(t *testing.T, opts ...jobOption) *job {
	t.Helper()
	j, err := newJob(jobConfig{Store: h.store, EnrolledSince: testSince, StateFile: h.stateFile, Textfile: h.textfile, Logger: capturedLog(h.logs)},
		append([]jobOption{withClock(func() time.Time { return testNow })}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func (h *harness) writeNodeState(t *testing.T, s state) {
	t.Helper()
	if err := os.WriteFile(h.stateFile, mustJSON(t, s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) bucketState(t *testing.T) state {
	t.Helper()
	body, ok := h.store.stateBody()
	if !ok {
		t.Fatal("the bucket has no state")
	}
	s, err := decodeState(body, "in the test bucket")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (h *harness) nodeState(t *testing.T) state {
	t.Helper()
	body, err := os.ReadFile(h.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := decodeState(body, "in the test node file")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (h *harness) writeOldTextfile(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.textfile, []byte(metrics(99, testNow.Add(-time.Hour))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) assertOldTextfileKept(t *testing.T) {
	t.Helper()
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(99, testNow.Add(-time.Hour)) {
		t.Fatalf("a failed run must leave the dashboard file as it was: %q, %v", got, err)
	}
}

func (h *harness) assertTextfile(t *testing.T, registered int) {
	t.Helper()
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(registered, testNow) {
		t.Fatalf("textfile = %q, %v, want %q", got, err, metrics(registered, testNow))
	}
}

func names(s state) string {
	var out []string
	for name := range s.Names {
		out = append(out, name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestJob_Run_TheFirstRunCountsCertifiedNamesEnrolledSinceTheDay(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "atday", testSince, testSince, "letsencrypt")
	h.store.putName(t, "later", testSince.Add(26*time.Hour), testSince.Add(26*time.Hour), "gts")
	h.store.putNameValidUntil(t, "expired", testSince.Add(time.Hour), testSince.Add(time.Hour), "zerossl", testNow.Add(-time.Hour))
	h.store.putName(t, "before", testSince.Add(-time.Nanosecond), testSince.Add(-time.Nanosecond), "letsencrypt")
	h.store.putName(t, "nocert", testSince.Add(time.Hour), testSince.Add(time.Hour), "")
	h.store.getErr[namesPrefix+"gone"] = bucket.ErrNotFound
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.assertTextfile(t, 3)
	for _, s := range []state{h.bucketState(t), h.nodeState(t)} {
		if names(s) != "atday,expired,later" || s.EnrolledSince != "2026-11-06" || !s.ReadFrom.Equal(testNow.Add(-clockSkew)) {
			t.Fatalf("state = %+v", s)
		}
		if !s.Names["later"].Equal(testSince.Add(26 * time.Hour)) {
			t.Fatalf("the state must keep each name's enrollment time: %+v", s.Names)
		}
	}
	info, err := os.Stat(h.stateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the node copy of the state must be private: %v, %v", info.Mode().Perm(), err)
	}
	for _, want := range []string{"no state is stored yet, so this run starts a new one from the first counted day",
		"counted the registered phones for the dashboard", "registered=3 new=3 names_listed=6 names_read=6 enrolled_since=2026-11-06"} {
		if !strings.Contains(h.logs.String(), want) {
			t.Fatalf("logs = %s, want %q", h.logs.String(), want)
		}
	}
}

func TestJob_Run_TheFirstRunSkipsRecordsLastWrittenBeforeTheDayLessTheClockSkew(t *testing.T) {
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
	h.assertTextfile(t, 1)
}

func TestJob_Run_ResumesFromTheStoredStateAndNeverRereadsACountedName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	readFrom := testNow.Add(-2 * time.Hour)
	h.store.putState(t, state{EnrolledSince: "2026-11-06", ReadFrom: readFrom, Names: map[string]time.Time{"counted": testSince}})
	h.store.putName(t, "counted", testSince, testNow.Add(-time.Minute), "gts")
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "letsencrypt")
	h.store.putName(t, "stale", testSince.Add(time.Hour), readFrom.Add(-time.Nanosecond), "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.store.readKeys(), ","); got != "names/fresh" {
		t.Fatalf("records read = %s, want only the new record written since the state's read-from time", got)
	}
	h.assertTextfile(t, 2)
	if s := h.bucketState(t); names(s) != "counted,fresh" || !s.ReadFrom.Equal(testNow.Add(-clockSkew)) {
		t.Fatalf("state = %+v", s)
	}
}

func TestJob_Run_KeepsCountingNamesWhoseRecordsArePurged(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-2 * time.Hour),
		Names: map[string]time.Time{"purged1": testSince, "purged2": testSince.Add(time.Hour)}})
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.assertTextfile(t, 2)
	if s := h.bucketState(t); names(s) != "purged1,purged2" {
		t.Fatalf("state = %+v", s)
	}
}

func TestJob_Run_MergesTheBucketAndNodeCopiesAndReadsFromTheOlderPoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-time.Hour), Names: map[string]time.Time{"a": testSince}})
	h.writeNodeState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-3 * time.Hour), Names: map[string]time.Time{"b": testSince}})
	h.store.putName(t, "between", testNow.Add(-2*time.Hour), testNow.Add(-2*time.Hour), "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.store.readKeys(), ","); got != "names/between" {
		t.Fatalf("records read = %s, want the record written after the older read-from time", got)
	}
	h.assertTextfile(t, 3)
	for _, s := range []state{h.bucketState(t), h.nodeState(t)} {
		if names(s) != "a,b,between" {
			t.Fatalf("state = %+v", s)
		}
	}
}

func TestJob_Run_PutsAStateMissingFromTheBucketBackFromTheNodeCopy(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeNodeState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-2 * time.Hour), Names: map[string]time.Time{"a": testSince}})
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.bucketState(t); names(s) != "a" {
		t.Fatalf("bucket state = %+v", s)
	}
	h.assertTextfile(t, 1)
	if !strings.Contains(h.logs.String(), "the state is missing from the bucket, so this run starts from this node's copy and a successful run puts it back") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_StartsFromTheBucketCopyWhenTheNodeHasNone(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-2 * time.Hour), Names: map[string]time.Time{"a": testSince}})
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.nodeState(t); names(s) != "a" {
		t.Fatalf("node state = %+v", s)
	}
	if !strings.Contains(h.logs.String(), "this node has no copy of the state yet, so it starts from the bucket's") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_AcceptsAStoredStateWithoutNames(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.objects[stateKey] = []byte(`{"enrolled_since":"2026-11-06","read_from":"2026-11-07T09:00:00Z"}`)
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.assertTextfile(t, 1)
	if s := h.bucketState(t); names(s) != "fresh" {
		t.Fatalf("state = %+v", s)
	}
}

func TestJob_Run_AnUnreadableNodeCopyStopsTheRunAndChangesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putState(t, state{EnrolledSince: "2026-11-06", ReadFrom: testNow.Add(-2 * time.Hour), Names: map[string]time.Time{"a": testSince}})
	before, _ := h.store.stateBody()
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	if err := os.MkdirAll(h.stateFile, 0o700); err != nil {
		t.Fatal(err)
	}
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read this node's copy of the state") {
		t.Fatalf("run = %v, want the node read error", err)
	}
	if after, _ := h.store.stateBody(); !bytes.Equal(after, before) {
		t.Fatalf("the bucket copy must stay as it was: %q", after)
	}
	h.assertOldTextfileKept(t)
}

func TestJob_Run_RefusesABadStateAndChangesNothing(t *testing.T) {
	t.Parallel()
	other := mustJSON(t, state{EnrolledSince: "2026-10-01", ReadFrom: testNow.Add(-time.Hour), Names: map[string]time.Time{"a": testSince}})
	tests := []struct {
		name   string
		bucket []byte
		node   []byte
		want   string
	}{
		{name: "the bucket copy counts from another day", bucket: other,
			want: "the state in the bucket counts from 2026-10-01 but this node is set to count from 2026-11-06, so the run stops without changing it"},
		{name: "the node copy counts from another day", node: other,
			want: "the state on this node counts from 2026-10-01 but this node is set to count from 2026-11-06, so the run stops without changing it"},
		{name: "the bucket copy does not decode", bucket: []byte("{"),
			want: "decode the state in the bucket at registered-phones/state.json, so the run stops without changing it"},
		{name: "the node copy does not decode", node: []byte("{"), want: "decode the state on this node at"},
		{name: "the bucket copy has no day", bucket: []byte(`{"names":{}}`),
			want: "the state in the bucket at registered-phones/state.json has no first counted day or no read-from time"},
		{name: "the node copy has no read-from time", node: []byte(`{"enrolled_since":"2026-11-06","names":{}}`),
			want: "has no first counted day or no read-from time"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
			if tc.bucket != nil {
				h.store.objects[stateKey] = tc.bucket
			}
			if tc.node != nil {
				if err := os.WriteFile(h.stateFile, tc.node, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			h.writeOldTextfile(t)
			err := h.job.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want an error containing %q", err, tc.want)
			}
			h.assertOldTextfileKept(t)
			body, ok := h.store.stateBody()
			if ok != (tc.bucket != nil) || ok && !bytes.Equal(body, tc.bucket) {
				t.Fatalf("the bucket copy must stay as it was: %q", body)
			}
			nodeBody, err := os.ReadFile(h.stateFile)
			if tc.node == nil && !errors.Is(err, os.ErrNotExist) || tc.node != nil && !bytes.Equal(nodeBody, tc.node) {
				t.Fatalf("the node copy must stay as it was: %q, %v", nodeBody, err)
			}
		})
	}
}

func TestJob_Run_AFailureLeavesTheStateAndTheDashboardFileAsTheyWere(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, f *fakeStore)
		want    string
		wantLog []string
	}{
		{name: "the state cannot be read", setup: func(_ *testing.T, f *fakeStore) { f.getErr[stateKey] = errors.New("read down") },
			want: "read the state from the bucket: read down"},
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
		}, want: "reading the name record names/ok crashed", wantLog: []string{`msg="` + crashedMsg + `"`, "key=names/ok", "panic=boom"}},
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
			h.assertOldTextfileKept(t)
			if _, ok := h.store.stateBody(); ok {
				t.Fatal("a failed run must not save a state")
			}
			if _, err := os.Stat(h.stateFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a failed run must not save a node copy: %v", err)
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(h.logs.String(), want) {
					t.Fatalf("logs = %s, want %q", h.logs.String(), want)
				}
			}
		})
	}
}

func TestJob_Run_ReportsEveryRecordThatFailed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.getErr[namesPrefix+"bad1"] = errors.New("read down one")
	h.store.objects[namesPrefix+"junk"] = []byte("{")
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read the name record names/bad1: read down one") ||
		!strings.Contains(err.Error(), "decode the name record names/junk") {
		t.Fatalf("run = %v, want both failed records", err)
	}
	h.assertOldTextfileKept(t)
}

func unflushedFor(target string) fileWriter {
	return func(path string, data []byte, mode os.FileMode) error {
		if err := atomicfile.Write(path, data, mode); err != nil {
			return err
		}
		if path == target {
			return fmt.Errorf("%w: test flush failure", atomicfile.ErrNotFlushed)
		}
		return nil
	}
}

func TestJob_Run_AnUnflushedDashboardFileIsAWarningNotAFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.job = h.newJob(t, withWriter(unflushedFor(h.textfile)))
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatalf("run = %v, want success", err)
	}
	h.assertTextfile(t, 1)
	for _, want := range []string{"wrote this node's dashboard file but could not flush it to disk, so a crash could lose it until the next run",
		"counted the registered phones for the dashboard"} {
		if !strings.Contains(h.logs.String(), want) {
			t.Fatalf("logs = %s, want %q", h.logs.String(), want)
		}
	}
}

func TestJob_Run_AnUnflushedNodeStateIsAWarningAndTheBucketCopyIsSaved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.job = h.newJob(t, withWriter(unflushedFor(h.stateFile)))
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	if err := h.job.run(context.Background()); err != nil {
		t.Fatalf("run = %v, want success", err)
	}
	if s := h.bucketState(t); names(s) != "fresh" {
		t.Fatalf("bucket state = %+v", s)
	}
	if s := h.nodeState(t); names(s) != "fresh" {
		t.Fatalf("node state = %+v", s)
	}
	h.assertTextfile(t, 1)
	if !strings.Contains(h.logs.String(), "saved this node's copy of the state but could not flush it to disk, so a crash could lose it; the bucket copy is saved next") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_ABucketSaveFailureKeepsTheNewStateOnTheNode(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	h.store.putErr[stateKey] = errors.New("put down")
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "save the state in the bucket: put down") {
		t.Fatalf("run = %v, want the bucket save error", err)
	}
	if s := h.nodeState(t); names(s) != "fresh" {
		t.Fatalf("node state = %+v, want the new name kept on the node", s)
	}
	h.assertOldTextfileKept(t)
}

func TestJob_Run_ANodeSaveFailureStillSavesTheBucketCopy(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.stateFile = filepath.Join(t.TempDir(), "missing", "state.json")
	h.job = h.newJob(t)
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "save the state on this node") {
		t.Fatalf("run = %v, want the node save error", err)
	}
	if s := h.bucketState(t); names(s) != "fresh" {
		t.Fatalf("bucket state = %+v, want the new name kept in the bucket", s)
	}
	h.assertOldTextfileKept(t)
}

func TestJob_Run_ATimeLimitEndsTheRunAndSaysSo(t *testing.T) {
	t.Parallel()
	h := newHarness(t, withTimeout(20*time.Millisecond))
	h.store.putName(t, "slow", testSince, testSince, "gts")
	h.store.get = func(ctx context.Context, key string) error {
		if key == stateKey {
			return nil
		}
		<-ctx.Done()
		return ctx.Err()
	}
	h.writeOldTextfile(t)
	err := h.job.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the run did not finish within 20ms") {
		t.Fatalf("run = %v, want the time-limit error", err)
	}
	h.assertOldTextfileKept(t)
}

func TestJob_Run_ACancelledRunIsNotCalledATimeout(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "slow", testSince, testSince, "gts")
	ctx, cancel := context.WithCancel(context.Background())
	h.store.get = func(ctx context.Context, key string) error {
		if key == stateKey {
			return nil
		}
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	err := h.job.run(ctx)
	if err == nil || strings.Contains(err.Error(), "did not finish within") || !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %v, want a plain cancellation", err)
	}
}

func TestJob_Run_AnUnwritableDashboardFileFailsAfterTheStateIsSaved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.textfile = filepath.Join(t.TempDir(), "missing", "arc_registered_phones.prom")
	h.job = h.newJob(t)
	h.store.putName(t, "fresh", testNow.Add(-time.Hour), testNow.Add(-time.Hour), "gts")
	if err := h.job.run(context.Background()); err == nil || !strings.Contains(err.Error(), "write the dashboard file") {
		t.Fatalf("run = %v, want a write error", err)
	}
	if s := h.bucketState(t); names(s) != "fresh" {
		t.Fatalf("bucket state = %+v", s)
	}
}

func TestJob_Run_SkipsAKeyWithoutAName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.objects[namesPrefix] = []byte("{")
	h.store.modified[namesPrefix] = testNow
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.store.readKeys(); len(got) != 0 {
		t.Fatalf("records read = %v, want none", got)
	}
	h.assertTextfile(t, 0)
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
	h.store.get = func(ctx context.Context, key string) error {
		if key == stateKey {
			return nil
		}
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
	h.assertTextfile(t, 3*parallelReads)
}

func TestNewJob_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	valid := jobConfig{Store: newFakeStore(), EnrolledSince: testSince, StateFile: "/tmp/state.json", Textfile: "/tmp/x.prom", Logger: testLog()}
	tests := []struct {
		name   string
		change func(*jobConfig)
		opts   []jobOption
		want   string
	}{
		{name: "no store", change: func(c *jobConfig) { c.Store = nil }, want: "the object store is missing"},
		{name: "no first day", change: func(c *jobConfig) { c.EnrolledSince = time.Time{} }, want: "the first counted day is missing"},
		{name: "no state file", change: func(c *jobConfig) { c.StateFile = "" }, want: "the state file path is empty"},
		{name: "no textfile", change: func(c *jobConfig) { c.Textfile = "" }, want: "the dashboard file path is empty"},
		{name: "no logger", change: func(c *jobConfig) { c.Logger = nil }, want: "the logger is missing"},
		{name: "no clock", change: func(*jobConfig) {}, opts: []jobOption{withClock(nil)}, want: "the clock is missing"},
		{name: "no time limit", change: func(*jobConfig) {}, opts: []jobOption{withTimeout(0)}, want: "the time limit 0s is not positive"},
		{name: "no file writer", change: func(*jobConfig) {}, opts: []jobOption{withWriter(nil)}, want: "the file writer is missing"},
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
