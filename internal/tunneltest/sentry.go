package tunneltest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
)

type SentryTransport struct {
	mu      sync.Mutex
	events  []*sentry.Event
	flushes int
}

func (m *SentryTransport) Flush(time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushes++
	return true
}

func (m *SentryTransport) FlushWithContext(context.Context) bool { return m.Flush(0) }
func (m *SentryTransport) Configure(sentry.ClientOptions)        {}
func (m *SentryTransport) Close()                                {}

func (m *SentryTransport) SendEvent(e *sentry.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

func (m *SentryTransport) Events(typ string) []*sentry.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*sentry.Event
	for _, e := range m.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func (m *SentryTransport) Flushes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

func NewReporter(t testing.TB, tracesSampleRate float64) (*report.Reporter, *SentryTransport) {
	t.Helper()
	tr := &SentryTransport{}
	rep, err := report.New(report.Config{DSN: "https://public@example.test/1", Environment: "test", Release: "tunneld@test", ServerName: "host-1",
		Node: "node-1", TracesSampleRate: tracesSampleRate}, report.WithTransport(tr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close(context.Background(), Logger()) })
	return rep, tr
}
