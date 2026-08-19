package store

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	asyncLogWorkers  = 8
	asyncLogQueue    = 5000
	asyncLogAttempts = 5
	asyncLogBackoff  = time.Second // doubles per retry: 1s, 2s, 4s, 8s
)

// AsyncConnLog decouples connection-log writes from the data/teardown paths: PutConnLog enqueues and
// returns immediately; a fixed worker pool drains with per-item exponential retry. A FULL queue drops
// the new event (never blocks a caller) and reports it via onDrop; Drain flushes the queue at
// shutdown (bounded by ctx) so end events are not lost.
type AsyncConnLog struct {
	inner  ConnLogStore
	onDrop func()
	logger *slog.Logger

	mu     sync.RWMutex
	closed bool
	ch     chan Event
	wg     sync.WaitGroup
}

func NewAsyncConnLog(inner ConnLogStore, onDrop func(), logger *slog.Logger) *AsyncConnLog {
	if onDrop == nil {
		onDrop = func() {}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	a := &AsyncConnLog{inner: inner, onDrop: onDrop, logger: logger, ch: make(chan Event, asyncLogQueue)}
	for range asyncLogWorkers {
		a.wg.Add(1)
		go a.worker()
	}
	return a
}

// PutConnLog enqueues (drop-newest on a full queue). Always returns nil: delivery is the workers' job.
func (a *AsyncConnLog) PutConnLog(_ context.Context, ev Event) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.onDrop()
		return nil
	}
	select {
	case a.ch <- ev:
	default:
		a.onDrop()
	}
	return nil
}

func (a *AsyncConnLog) worker() {
	defer a.wg.Done()
	for ev := range a.ch {
		backoff := asyncLogBackoff
		var err error
		for attempt := 0; attempt < asyncLogAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(backoff)
				backoff *= 2
			}
			if err = a.inner.PutConnLog(context.Background(), ev); err == nil {
				break
			}
		}
		if err != nil {
			a.onDrop()
			a.logger.Warn("conn-log write dropped after retries", "tunnel", ev.Tunnel, "event", ev.Event, "err", err)
		}
	}
}

// Drain stops intake and waits for the queue to flush or ctx to expire (server shutdown).
func (a *AsyncConnLog) Drain(ctx context.Context) {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.ch)
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
