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

var testSince = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	listErr error
	getErr  map[string]error
	get     func(ctx context.Context, key string) error
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, getErr: map[string]error{}}
}

func (f *fakeStore) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	for k := range f.getErr {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *fakeStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.get != nil {
		if err := f.get(ctx, key); err != nil {
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

func (f *fakeStore) putName(t *testing.T, name string, enrolled time.Time, ca string) {
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
}

type harness struct {
	store    *fakeStore
	textfile string
	logs     *bytes.Buffer
	job      *job
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{store: newFakeStore(), textfile: filepath.Join(t.TempDir(), "arc_registered_phones.prom"), logs: &bytes.Buffer{}}
	j, err := newJob(jobConfig{Store: h.store, EnrolledSince: testSince, Textfile: h.textfile, Logger: slog.New(slog.NewTextHandler(h.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	h.job = j
	return h
}

func (h *harness) writeOldTextfile(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.textfile, []byte(metrics(99)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestJob_Run_CountsCertifiedNamesEnrolledSinceTheDay(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.putName(t, "atday", testSince, "letsencrypt")
	h.store.putName(t, "later", testSince.Add(26*time.Hour), "gts")
	h.store.putName(t, "expired", testSince.Add(time.Hour), "zerossl")
	h.store.putName(t, "before", testSince.Add(-time.Nanosecond), "letsencrypt")
	h.store.putName(t, "nocert", testSince.Add(time.Hour), "")
	h.store.getErr[namesPrefix+"gone"] = bucket.ErrNotFound
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(h.textfile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != metrics(3) {
		t.Fatalf("textfile = %q, want %q", got, metrics(3))
	}
	if !strings.Contains(h.logs.String(), "counted the registered phones for the dashboard") ||
		!strings.Contains(h.logs.String(), "registered=3 names_read=6 enrolled_since=2026-11-06") {
		t.Fatalf("logs = %s", h.logs.String())
	}
}

func TestJob_Run_AnEmptyRegistryCountsZero(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.job.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(0) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestJob_Run_AFailureRemovesTheDashboardFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(t *testing.T, f *fakeStore)
		want  string
	}{
		{name: "the list fails", setup: func(_ *testing.T, f *fakeStore) { f.listErr = errors.New("list down") }, want: "list the name registry: list down"},
		{name: "a read fails", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, "gts")
			f.getErr[namesPrefix+"bad"] = errors.New("read down")
		}, want: "read the name record names/bad: read down"},
		{name: "a record does not decode", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, "gts")
			f.objects[namesPrefix+"junk"] = []byte("{")
		}, want: "decode the name record names/junk"},
		{name: "a read panics", setup: func(t *testing.T, f *fakeStore) {
			f.putName(t, "ok", testSince, "gts")
			f.get = func(_ context.Context, key string) error {
				if key == namesPrefix+"ok" {
					panic("boom")
				}
				return nil
			}
		}, want: "reading the name record names/ok crashed"},
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
			if _, err := os.Stat(h.textfile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the old dashboard file must be removed, stat = %v", err)
			}
		})
	}
}

func TestJob_Run_AnUnwritableDashboardFileFails(t *testing.T) {
	t.Parallel()
	j, err := newJob(jobConfig{Store: newFakeStore(), EnrolledSince: testSince,
		Textfile: filepath.Join(t.TempDir(), "missing", "arc_registered_phones.prom"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.run(context.Background()); err == nil || !strings.Contains(err.Error(), "write the dashboard file") {
		t.Fatalf("run = %v, want a write error", err)
	}
}

func TestJob_Run_ReadsUpToTheParallelLimitAtOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for i := range 3 * parallelReads {
		h.store.putName(t, fmt.Sprintf("n%02d", i), testSince, "gts")
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
	if got, err := os.ReadFile(h.textfile); err != nil || string(got) != metrics(3*parallelReads) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestNewJob_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	valid := jobConfig{Store: newFakeStore(), EnrolledSince: testSince, Textfile: "/tmp/x.prom", Logger: logger}
	tests := []struct {
		name   string
		change func(*jobConfig)
		want   string
	}{
		{name: "no store", change: func(c *jobConfig) { c.Store = nil }, want: "the object store is missing"},
		{name: "no first day", change: func(c *jobConfig) { c.EnrolledSince = time.Time{} }, want: "the first counted day is missing"},
		{name: "no textfile", change: func(c *jobConfig) { c.Textfile = "" }, want: "the dashboard file path is empty"},
		{name: "no logger", change: func(c *jobConfig) { c.Logger = nil }, want: "the logger is missing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := valid
			tc.change(&c)
			if _, err := newJob(c); err == nil || err.Error() != tc.want {
				t.Fatalf("newJob = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := newJob(valid); err != nil {
		t.Fatalf("a complete config must be accepted: %v", err)
	}
}
