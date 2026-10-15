package acme

import (
	"context"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

type trackKey struct{}

type orderTrack struct {
	name        limit.Bucket
	domain      limit.Bucket
	mu          sync.Mutex
	orderURL    string
	finalizeURL string
	finalizedAt time.Time
	lastPoll    time.Time
	created     bool
	cleanups    []func(context.Context) error
	limited     chan time.Duration
	done        chan struct{}
	once        sync.Once
}

type orderOutcome struct {
	created   bool
	finalized bool
	abandoned bool
}

func newOrderTrack(name, domain limit.Bucket) *orderTrack {
	return &orderTrack{name: name, domain: domain, limited: make(chan time.Duration, 1), done: make(chan struct{})}
}

func withTrack(ctx context.Context, t *orderTrack) context.Context {
	return context.WithValue(ctx, trackKey{}, t)
}

func trackFrom(ctx context.Context) *orderTrack {
	t, _ := ctx.Value(trackKey{}).(*orderTrack)
	return t
}

func withoutTrack(ctx context.Context) context.Context {
	return context.WithValue(ctx, trackKey{}, (*orderTrack)(nil))
}

func (t *orderTrack) abandon() { t.once.Do(func() { close(t.done) }) }

func (t *orderTrack) abandoned() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

func (t *orderTrack) signalLimited(d time.Duration) {
	select {
	case t.limited <- d:
	default:
	}
}

func (t *orderTrack) onAbandon(f func(context.Context) error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanups = append(t.cleanups, f)
}

func (t *orderTrack) takeCleanups() []func(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fs := t.cleanups
	t.cleanups = nil
	return fs
}

func (t *orderTrack) hasOrder() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.created
}

func (t *orderTrack) setOrder(orderURL, finalizeURL string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.orderURL, t.finalizeURL, t.created = orderURL, finalizeURL, true
}

func (t *orderTrack) isFinalize(u string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finalizeURL != "" && u == t.finalizeURL
}

func (t *orderTrack) markFinalized(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finalizedAt = at
}

func (t *orderTrack) isPoll(u string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.finalizedAt.IsZero() && u == t.orderURL
}

func (t *orderTrack) pollDue(first, every time.Duration) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	due := t.finalizedAt.Add(first)
	if !t.lastPoll.IsZero() {
		if next := t.lastPoll.Add(every); next.After(due) {
			due = next
		}
	}
	return due
}

func (t *orderTrack) markPoll(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastPoll = at
}

func (t *orderTrack) outcome() orderOutcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	return orderOutcome{created: t.created, finalized: !t.finalizedAt.IsZero(), abandoned: t.abandoned()}
}
