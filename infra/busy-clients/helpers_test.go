package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go4.org/netipx"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const testBotToken = "123:sekret-bot-token"

var (
	testZone = time.FixedZone("TEST", 3600)
	testNow  = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testLogger(logs io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logs), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	listed  []string
	listErr error
	getErr  map[string]error
	getHook func(ctx context.Context, key string) error
	putErr  error
	puts    int
	gets    []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, getErr: map[string]error{}}
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
	for _, k := range s.listed {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *fakeStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	hook := s.getHook
	s.gets = append(s.gets, key)
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, key); err != nil {
			return nil, err
		}
	}
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

func (s *fakeStore) read(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.gets, key)
}

func (s *fakeStore) state(t *testing.T) alertedList {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var l alertedList
	if err := json.Unmarshal(s.objects[stateKey], &l); err != nil {
		t.Fatalf("decode the stored list: %v", err)
	}
	return l
}

func (s *fakeStore) setState(t *testing.T, l alertedList) {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	s.objects[stateKey] = b
}

func logKey(start time.Time, node string) string {
	start = start.UTC()
	return fmt.Sprintf("tunnel-logs/%04d/%02d/%02d/%s-%s.jsonl", start.Year(), start.Month(), start.Day(), start.Format(logNameLayout), node)
}

func jsonLine(ev store.Event) (string, error) {
	b, err := json.Marshal(ev)
	return string(b), err
}

func (s *fakeStore) addLog(t *testing.T, start time.Time, events ...store.Event) string {
	t.Helper()
	var b bytes.Buffer
	for _, ev := range events {
		line, err := jsonLine(ev)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	key := logKey(start, "0123456789abcdef")
	s.objects[key] = b.Bytes()
	return key
}

func publicStart(ip, tunnel, fp string, at time.Time) store.Event {
	return store.Event{Schema: 1, Event: "start", Type: "public", Tunnel: tunnel, TSStart: at, SrcIP: ip, SrcPort: 40000, TLSFP: fp}
}

func busy(ip string, connections, tunnels int, at time.Time) []store.Event {
	out := make([]store.Event, connections)
	for i := range out {
		out[i] = publicStart(ip, fmt.Sprintf("t%d", i%tunnels), "fp", at.Add(time.Duration(i)*time.Millisecond))
	}
	return out
}

type fakeMessenger struct {
	mu    sync.Mutex
	texts []string
	fail  func(text string) error
}

func (m *fakeMessenger) Send(_ context.Context, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		if err := m.fail(text); err != nil {
			return err
		}
	}
	m.texts = append(m.texts, text)
	return nil
}

func (m *fakeMessenger) sent() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.texts...)
}

type harness struct {
	store     *fakeStore
	messages  *fakeMessenger
	located   [][]netip.Addr
	ranges    []netip.Prefix
	rangesErr error
	exclude   []string
	rule      rule
	dailyHour int
	now       time.Time
	pauses    []time.Duration
	logs      *logBuffer
	opts      []jobOption
}

func newHarness() *harness {
	return &harness{
		store:     newFakeStore(),
		messages:  &fakeMessenger{},
		rule:      rule{connections: 500, spreadConnections: 100, spreadTunnels: 3},
		dailyHour: 23,
		now:       testNow,
		logs:      &logBuffer{},
	}
}

func (h *harness) job(t *testing.T) *job {
	t.Helper()
	j, err := newJob(jobConfig{
		Store:    h.store,
		Messages: h.messages,
		Ranges: func(context.Context) ([]netip.Prefix, error) {
			return h.ranges, h.rangesErr
		},
		Locate: func(_ context.Context, addrs []netip.Addr) []place {
			h.located = append(h.located, addrs)
			out := make([]place, len(addrs))
			for i, a := range addrs {
				out[i] = place{country: "XX", network: "AS64500 Example for " + a.String()}
			}
			return out
		},
		Exclude:   h.exclude,
		Rule:      h.rule,
		DailyHour: h.dailyHour,
		Node:      "n1",
		Location:  testZone,
		Logger:    testLogger(h.logs),
	},
		append([]jobOption{
			withClock(func() time.Time { return h.now }),
			withPause(time.Second, func(_ context.Context, d time.Duration) error {
				h.pauses = append(h.pauses, d)
				return nil
			}),
		}, h.opts...)...,
	)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func emptySet(t *testing.T, prefixes ...string) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		b.AddPrefix(netip.MustParsePrefix(p))
	}
	s, err := b.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
