package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	asyncLogWorkers        = 8
	asyncLogQueue          = 5000
	asyncLogAttempts       = 5
	defaultAsyncLogBackoff = time.Second // doubles per retry: 1s, 2s, 4s, 8s
	asyncLogBatchMax       = 100
	asyncLogBatchAge       = 5 * time.Minute
	defaultAsyncLogCheck   = time.Second
)

type batchKey struct {
	tunnel string
	day    string
}

type pendingBatch struct {
	batch   ConnLogBatch
	created time.Time
}

// AsyncConnLog decouples connection-log writes from the data/teardown paths: PutConnLog enqueues and
// returns immediately; a fixed worker pool drains with exponential retry. A FULL queue drops
// the new event (never blocks a caller) and reports it via onDrop; Drain flushes the queue at
// shutdown (bounded by ctx) so end events are not lost.
type AsyncConnLog struct {
	inner       ConnLogBatchStore
	nodeID      string
	onDrop      func(n int)
	logger      *slog.Logger
	backoffBase time.Duration
	now         func() time.Time
	checkEvery  time.Duration

	mu       sync.Mutex
	closed   bool
	buffered int
	pending  map[batchKey]*pendingBatch
	ready    chan ConnLogBatch
	stop     chan struct{}
	wg       sync.WaitGroup
}

// AsyncOption configures an AsyncConnLog (functional-options pattern).
type AsyncOption func(*AsyncConnLog) error

// WithBackoffBase sets the first retry backoff (default 1s; doubles per retry). Tests use a tiny
// value so the retry-exhaustion path runs in milliseconds rather than ~15s of real sleep.
func WithBackoffBase(d time.Duration) AsyncOption {
	return func(a *AsyncConnLog) error {
		if d < 0 {
			return fmt.Errorf("store: negative conn-log backoff %v", d)
		}
		a.backoffBase = d
		return nil
	}
}

func WithClock(now func() time.Time) AsyncOption {
	return func(a *AsyncConnLog) error {
		if now == nil {
			return errors.New("store: nil conn-log clock")
		}
		a.now = now
		return nil
	}
}

func WithAgeCheck(d time.Duration) AsyncOption {
	return func(a *AsyncConnLog) error {
		if d <= 0 {
			return fmt.Errorf("store: non-positive conn-log age check %v", d)
		}
		a.checkEvery = d
		return nil
	}
}

func NewAsyncConnLog(inner ConnLogBatchStore, nodeID string, onDrop func(n int), logger *slog.Logger, opts ...AsyncOption) (*AsyncConnLog, error) {
	if onDrop == nil {
		onDrop = func(int) {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &AsyncConnLog{inner: inner, nodeID: nodeID, onDrop: onDrop, logger: logger,
		backoffBase: defaultAsyncLogBackoff, now: time.Now, checkEvery: defaultAsyncLogCheck,
		pending: map[batchKey]*pendingBatch{}, ready: make(chan ConnLogBatch, asyncLogQueue),
		stop: make(chan struct{})}
	for _, o := range opts {
		if err := o(a); err != nil {
			return nil, err
		}
	}
	for range asyncLogWorkers {
		a.wg.Add(1)
		go a.worker()
	}
	a.wg.Add(1)
	go a.ager()
	return a, nil
}

// PutConnLog enqueues (drop-newest on a full queue). Always returns nil: delivery is the workers' job.
func (a *AsyncConnLog) PutConnLog(_ context.Context, ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.buffered >= asyncLogQueue {
		a.onDrop(1)
		return nil
	}
	at := ev.at()
	k := batchKey{tunnel: ev.Tunnel, day: at.Format(time.DateOnly)}
	p := a.pending[k]
	if p == nil {
		p = &pendingBatch{batch: ConnLogBatch{Tunnel: ev.Tunnel, NodeID: a.nodeID, First: at}, created: a.now()}
		a.pending[k] = p
	}
	p.batch.Events = append(p.batch.Events, ev)
	a.buffered++
	if len(p.batch.Events) >= asyncLogBatchMax {
		delete(a.pending, k)
		a.ready <- p.batch
	}
	return nil
}

func (a *AsyncConnLog) ager() {
	defer a.wg.Done()
	t := time.NewTicker(a.checkEvery)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
			a.flushAged()
		}
	}
}

func (a *AsyncConnLog) flushAged() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	now := a.now()
	for k, p := range a.pending {
		if now.Sub(p.created) >= asyncLogBatchAge {
			delete(a.pending, k)
			a.ready <- p.batch
		}
	}
}

func (a *AsyncConnLog) worker() {
	defer a.wg.Done()
	for b := range a.ready {
		backoff := a.backoffBase
		var err error
		for attempt := range asyncLogAttempts {
			if attempt > 0 {
				time.Sleep(backoff)
				backoff *= 2
			}
			if err = a.inner.PutConnLogBatch(context.Background(), b); err == nil {
				break
			}
		}
		a.mu.Lock()
		a.buffered -= len(b.Events)
		a.mu.Unlock()
		if err != nil {
			a.onDrop(len(b.Events))
			a.logger.Warn("conn-log batch dropped after retries", "tunnel", b.Tunnel,
				"day", b.First.Format(time.DateOnly), "node", b.NodeID, "events", len(b.Events), "err", err)
		}
	}
}

// Drain stops intake and waits for the queue to flush or ctx to expire (server shutdown).
func (a *AsyncConnLog) Drain(ctx context.Context) {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		for k, p := range a.pending {
			delete(a.pending, k)
			a.ready <- p.batch
		}
		close(a.ready)
		close(a.stop)
	}
	a.mu.Unlock()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		a.logger.Warn("conn-log drain incomplete at shutdown deadline")
	}
}
