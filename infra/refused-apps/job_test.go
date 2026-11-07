package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	listErr error
	getErr  map[string]error
	putErr  error
	puts    int
}

func (s *fakeStore) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *fakeStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.getErr[key]; err != nil {
		return nil, err
	}
	b, ok := s.objects[key]
	if !ok {
		return nil, bucket.ErrNotFound
	}
	return b, nil
}

func (s *fakeStore) Put(_ context.Context, key string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	s.puts++
	s.objects[key] = body
	return nil
}

func (s *fakeStore) list(t *testing.T) attemptList {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var l attemptList
	if err := json.Unmarshal(s.objects[listKey], &l); err != nil {
		t.Fatalf("decode the stored list: %v", err)
	}
	return l
}

type fakeMessenger struct {
	texts []string
	err   error
}

func (m *fakeMessenger) Send(_ context.Context, text string) error {
	if m.err != nil {
		return m.err
	}
	m.texts = append(m.texts, text)
	return nil
}

type harness struct {
	hideApps []string
	store    *fakeStore
	messages *fakeMessenger
	textfile string
	loads    int
	loadErr  error
	pauses   []time.Duration
	now      time.Time
	revoked  revokedSerials
	logger   *slog.Logger
}

func newHarness(t *testing.T, now time.Time) *harness {
	t.Helper()
	return &harness{
		store:    &fakeStore{objects: map[string][]byte{}, getErr: map[string]error{}},
		messages: &fakeMessenger{},
		textfile: filepath.Join(t.TempDir(), "arc_refused_apps.prom"),
		now:      now,
		revoked:  revokedSerials{},
		logger:   testLog(),
	}
}

func (h *harness) job(t *testing.T) *job {
	t.Helper()
	j, err := newJob(jobConfig{
		Store:    h.store,
		Messages: h.messages,
		Revocations: func(context.Context) (revocationList, error) {
			h.loads++
			return h.revoked, h.loadErr
		},
		Node:     "n2",
		Location: testZone,
		Textfile: h.textfile,
		HideApps: h.hideApps,
		Logger:   h.logger,
	},
		withClock(func() time.Time { return h.now }),
		withPause(time.Second, func(_ context.Context, d time.Duration) error {
			h.pauses = append(h.pauses, d)
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func (h *harness) addRecord(t *testing.T, key string, at time.Time, ip string) {
	t.Helper()
	h.store.objects["rejected-enroll/"+key] = evidenceJSON(t, evidence(t, at, ip, "attest-signer", goodChain()))
}

func (h *harness) setList(t *testing.T, l attemptList) {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	h.store.objects[listKey] = b
}

func TestJob_FirstRunReportsEverythingOnFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.addRecord(t, "a.json", at(5, 23, 29), "198.51.100.7")
	h.addRecord(t, "b.json", at(6, 21, 15), "203.0.113.9")
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.texts) != 1 || !strings.Contains(h.messages.texts[0], "This is the first report") || !strings.Contains(h.messages.texts[0], "2 new attempts.") {
		t.Fatalf("messages = %q", h.messages.texts)
	}
	l := h.store.list(t)
	if l.LastReport != "2026-11-07" || l.count() != 2 || len(l.Apps["dev.example.copy"]) != 2 {
		t.Fatalf("stored list = %+v", l)
	}
	if !l.Apps["dev.example.copy"][0].Verified || l.Apps["dev.example.copy"][0].Version != 20011770 {
		t.Fatalf("stored attempt = %+v", l.Apps["dev.example.copy"][0])
	}
	prom, err := os.ReadFile(h.textfile)
	if err != nil {
		t.Fatal(err)
	}
	want := `arc_refused_app_attempts{app="dev.example.copy",key="3031323334353637383961626364656630313233343536373839616263646566",version="20011770",ip="198.51.100.7"} 1`
	if !strings.Contains(string(prom), want+"\n") {
		t.Fatalf("dashboard file lacks %s:\n%s", want, prom)
	}
}

func TestJob_HiddenAppsStayOnFileButOutOfTheReportAndDashboard(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.hideApps = []string{"dev.example.own"}
	own := goodChain()
	own.app = "dev.example.own"
	h.addRecord(t, "a.json", at(6, 21, 15), "198.51.100.7")
	h.store.objects["rejected-enroll/b.json"] = evidenceJSON(t, evidence(t, at(6, 22, 0), "203.0.113.9", "attest-signer", own))
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.texts) != 1 || !strings.Contains(h.messages.texts[0], "1 new attempt.") || strings.Contains(h.messages.texts[0], "dev.example.own") {
		t.Fatalf("messages = %q, want only the attempt of the app that is not hidden", h.messages.texts)
	}
	l := h.store.list(t)
	if len(l.Apps["dev.example.own"]) != 1 || len(l.Apps["dev.example.copy"]) != 1 {
		t.Fatalf("stored list = %+v, want the hidden app kept on file", l)
	}
	prom, err := os.ReadFile(h.textfile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prom), "dev.example.own") || !strings.Contains(string(prom), `app="dev.example.copy"`) {
		t.Fatalf("dashboard file = %s, want only the app that is not hidden", prom)
	}
}

func TestJob_AReportAlreadySentTodayDoesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 30, 0, 0, testZone))
	h.addRecord(t, "a.json", at(6, 21, 15), "198.51.100.7")
	h.setList(t, attemptList{LastReport: "2026-11-07", Apps: map[string][]attempt{}})
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.texts) != 0 || h.store.puts != 0 || h.loads != 0 {
		t.Fatalf("messages %q, puts %d, revocation loads %d; want nothing done", h.messages.texts, h.store.puts, h.loads)
	}
	if _, err := os.Stat(h.textfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the dashboard file was touched: %v", err)
	}
}

func TestJob_ReportsOnlyNewAttemptsAndKeepsTheOldOnes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 6, 11, 0, 0, 0, testZone))
	h.addRecord(t, "a.json", at(5, 23, 29), "198.51.100.7")
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := attempt{At: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), IP: "203.0.113.1", Key: "aa", Version: 5}
	l := h.store.list(t)
	l.Apps["dev.example.gone"] = []attempt{old}
	h.setList(t, l)
	h.addRecord(t, "b.json", at(6, 21, 15), "203.0.113.9")
	h.now = time.Date(2026, 11, 7, 11, 0, 0, 0, testZone)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := h.messages.texts[len(h.messages.texts)-1]
	if !strings.Contains(last, "1 new attempt.") || !strings.Contains(last, "203.0.113.9") || strings.Contains(last, "198.51.100.7") {
		t.Fatalf("report = %s", last)
	}
	if strings.Contains(last, "(first time seen)") {
		t.Fatalf("a known app was marked as new: %s", last)
	}
	got := h.store.list(t)
	if got.count() != 3 || len(got.Apps["dev.example.gone"]) != 1 || got.LastReport != "2026-11-07" {
		t.Fatalf("stored list = %+v, want the expired attempt kept and both new ones", got)
	}
}

func TestJob_AQuietDayStillSendsAMessage(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.setList(t, attemptList{LastReport: "2026-11-06", Apps: map[string][]attempt{}})
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.texts) != 1 || !strings.Contains(h.messages.texts[0], "No new attempts.") {
		t.Fatalf("messages = %q", h.messages.texts)
	}
	if h.store.list(t).LastReport != "2026-11-07" {
		t.Fatal("the day was not marked as reported")
	}
}

func TestJob_ARunAfterMissedDaysCoversThem(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.setList(t, attemptList{LastReport: "2026-11-04", Apps: map[string][]attempt{}})
	h.addRecord(t, "a.json", at(5, 9, 0), "198.51.100.7")
	h.addRecord(t, "b.json", at(6, 9, 0), "203.0.113.9")
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := h.messages.texts[0]
	for _, want := range []string{"covers the 2 days in between.", "<td>Thu 5 Nov</td>", "<td>Fri 6 Nov</td>", "2 new attempts."} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestJob_ALongReportGoesOutInNumberedParts(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.setList(t, attemptList{LastReport: "2026-11-06", Apps: map[string][]attempt{}})
	ev := evidence(t, at(6, 10, 0), "", "attest-signer", goodChain())
	for i := range 600 {
		ev.TS = at(6, 10, 0).Add(time.Duration(i) * time.Second)
		ev.SrcIP = "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256)
		h.store.objects["rejected-enroll/r"+strconv.Itoa(i)+".json"] = evidenceJSON(t, ev)
	}
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := len(h.messages.texts)
	if n < 2 {
		t.Fatalf("got %d messages, want several parts", n)
	}
	for i, text := range h.messages.texts {
		if !strings.HasPrefix(text, "<p>Part "+strconv.Itoa(i+1)+" of "+strconv.Itoa(n)) {
			t.Fatalf("message %d = %.80q, want part %d of %d", i+1, text, i+1, n)
		}
		if utf8.RuneCountInString(text) > richMessageRunes || strings.Count(text, "<tr>") >= richMessageBlocks {
			t.Fatalf("message %d is over Telegram's limits", i+1)
		}
	}
	if got := strings.Count(strings.Join(h.messages.texts, ""), "<td>10.0."); got != 600 {
		t.Fatalf("%d address rows, want each of the 600 once", got)
	}
	if len(h.pauses) != n-1 {
		t.Fatalf("pauses = %d, want one between each of the %d messages", len(h.pauses), n)
	}
}

func TestJob_Failures(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		name     string
		setup    func(*testing.T, *harness)
		wantErr  string
		wantSent bool
	}{
		{
			name:    "an unreadable stored list is never overwritten",
			setup:   func(_ *testing.T, h *harness) { h.store.objects[listKey] = []byte("{not json") },
			wantErr: "decode the attempt list",
		},
		{
			name:    "a failed read of the stored list is never taken for a first run",
			setup:   func(_ *testing.T, h *harness) { h.store.getErr[listKey] = boom },
			wantErr: "read the attempt list",
		},
		{
			name:    "an unavailable revocation list stops the run",
			setup:   func(_ *testing.T, h *harness) { h.loadErr = boom },
			wantErr: "load the attestation revocation list",
		},
		{
			name:    "a failed listing stops the run",
			setup:   func(_ *testing.T, h *harness) { h.store.listErr = boom },
			wantErr: "list the refusal records",
		},
		{
			name: "a failed record read stops the run",
			setup: func(t *testing.T, h *harness) {
				h.addRecord(t, "a.json", at(6, 9, 0), "198.51.100.7")
				h.store.getErr["rejected-enroll/a.json"] = boom
			},
			wantErr: "read the refusal record rejected-enroll/a.json",
		},
		{
			name:    "an unreadable record stops the run",
			setup:   func(_ *testing.T, h *harness) { h.store.objects["rejected-enroll/a.json"] = []byte("{not json") },
			wantErr: "decode the refusal record rejected-enroll/a.json",
		},
		{
			name:    "a failed send saves nothing, so the next run sends again",
			setup:   func(_ *testing.T, h *harness) { h.messages.err = boom },
			wantErr: "send the report",
		},
		{
			name:     "a failed save after the send says the attempts come again",
			setup:    func(_ *testing.T, h *harness) { h.store.putErr = boom },
			wantErr:  "the next run sends these attempts again",
			wantSent: true,
		},
		{
			name:     "a failed dashboard write is an error",
			setup:    func(_ *testing.T, h *harness) { h.textfile = filepath.Join(h.textfile, "missing", "x.prom") },
			wantErr:  "write the dashboard file",
			wantSent: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
			tc.setup(t, h)
			before := string(h.store.objects[listKey])
			err := h.job(t).run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
			if sent := len(h.messages.texts) > 0; sent != tc.wantSent {
				t.Fatalf("sent = %v, want %v", sent, tc.wantSent)
			}
			if !tc.wantSent && string(h.store.objects[listKey]) != before {
				t.Fatal("the stored list changed although nothing was reported")
			}
		})
	}
}

func TestJob_ARecordGoneSinceTheListingIsSkipped(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Date(2026, 11, 7, 11, 0, 0, 0, testZone))
	h.addRecord(t, "a.json", at(6, 9, 0), "198.51.100.7")
	h.store.getErr["rejected-enroll/a.json"] = bucket.ErrNotFound
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.messages.texts[0], "No new attempts.") {
		t.Fatalf("report = %s", h.messages.texts[0])
	}
}

func TestNewJob_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	ok := func() jobConfig {
		return jobConfig{
			Store: &fakeStore{}, Messages: &fakeMessenger{},
			Revocations: func(context.Context) (revocationList, error) { return revokedSerials{}, nil },
			Node:        "n1", Location: testZone, Textfile: "/x.prom", Logger: testLog(),
		}
	}
	tests := []struct {
		name   string
		mutate func(*jobConfig)
		opts   []jobOption
	}{
		{name: "store", mutate: func(c *jobConfig) { c.Store = nil }},
		{name: "messenger", mutate: func(c *jobConfig) { c.Messages = nil }},
		{name: "revocations", mutate: func(c *jobConfig) { c.Revocations = nil }},
		{name: "node", mutate: func(c *jobConfig) { c.Node = "" }},
		{name: "location", mutate: func(c *jobConfig) { c.Location = nil }},
		{name: "textfile", mutate: func(c *jobConfig) { c.Textfile = "" }},
		{name: "logger", mutate: func(c *jobConfig) { c.Logger = nil }},
		{name: "empty hidden app", mutate: func(c *jobConfig) { c.HideApps = []string{"dev.example.own", ""} }},
		{name: "clock", mutate: func(*jobConfig) {}, opts: []jobOption{withClock(nil)}},
		{name: "sleep", mutate: func(*jobConfig) {}, opts: []jobOption{withPause(time.Second, nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := ok()
			tc.mutate(&cfg)
			if _, err := newJob(cfg, tc.opts...); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
