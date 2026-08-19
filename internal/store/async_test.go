package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// captureWarn returns a logger writing Warn+Error records into the returned buffer. slog serializes
// concurrent handler writes, so worker goroutines may log into it safely; read it only after Drain.
func captureWarn() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// blockingLog blocks every PutConnLog until release is closed (a stalled inner store).
type blockingLog struct {
	release chan struct{}
	writes  atomic.Int64
}

func (b *blockingLog) PutConnLog(_ context.Context, _ store.Event) error {
	<-b.release
	b.writes.Add(1)
	return nil
}

// countingLog records how many events it wrote.
type countingLog struct{ writes atomic.Int64 }

func (c *countingLog) PutConnLog(_ context.Context, _ store.Event) error {
	c.writes.Add(1)
	return nil
}

func (c *countingLog) count() int64 { return c.writes.Load() }

// flakyLog fails the first failFirst attempts (across all events), then succeeds.
type flakyLog struct {
	failFirst int64
	attempts  atomic.Int64
	writes    atomic.Int64
}

func (f *flakyLog) PutConnLog(_ context.Context, _ store.Event) error {
	if f.attempts.Add(1) <= f.failFirst {
		return errors.New("inject: conn-log write failed")
	}
	f.writes.Add(1)
	return nil
}

func TestAsyncConnLog_EnqueueNonBlocking(t *testing.T) {
	release := make(chan struct{})
	inner := &blockingLog{release: release}
	a := store.NewAsyncConnLog(inner, nil, nil)

	done := make(chan struct{})
	go func() {
		_ = a.PutConnLog(context.Background(), store.Event{Tunnel: "t"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PutConnLog must not block even when the inner store stalls")
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.Drain(ctx)
}

func TestAsyncConnLog_FullQueueDropsNewest(t *testing.T) {
	block := make(chan struct{})
	inner := &blockingLog{release: block} // stays blocked → workers stall, the buffer fills
	var drops atomic.Int64
	a := store.NewAsyncConnLog(inner, func() { drops.Add(1) }, nil)

	// The 8 workers each pull one item and stall; the 5000-slot buffer then fills. Enqueueing well past
	// (buffer + workers) guarantees at least one drop, and no enqueue blocks.
	for range 5000 + 8 + 64 {
		_ = a.PutConnLog(context.Background(), store.Event{})
	}
	if drops.Load() == 0 {
		t.Fatal("a full queue must drop-newest and fire onDrop")
	}

	close(block)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.Drain(ctx)
}

func TestAsyncConnLog_RetriesThenDrops(t *testing.T) {
	t.Run("retries then succeeds", func(t *testing.T) {
		t.Parallel()
		inner := &flakyLog{failFirst: 1} // fail attempt 0, succeed attempt 1 (one backoff)
		var drops atomic.Int64
		a := store.NewAsyncConnLog(inner, func() { drops.Add(1) }, nil, store.WithBackoffBase(time.Millisecond))
		_ = a.PutConnLog(context.Background(), store.Event{Tunnel: "t"})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Drain(ctx)
		if drops.Load() != 0 {
			t.Errorf("a write that succeeds on retry must not drop, drops = %d", drops.Load())
		}
		if got := inner.writes.Load(); got != 1 {
			t.Errorf("the event must be written exactly once on the successful retry, got %d", got)
		}
		if got := inner.attempts.Load(); got != 2 {
			t.Errorf("expected 2 attempts (one failure then success), got %d", got)
		}
	})

	t.Run("permanent failure drops", func(t *testing.T) {
		t.Parallel()
		inner := &flakyLog{failFirst: 1 << 30} // always fail: all 5 attempts (tiny backoff → milliseconds)
		var drops atomic.Int64
		log, buf := captureWarn()
		a := store.NewAsyncConnLog(inner, func() { drops.Add(1) }, log, store.WithBackoffBase(time.Millisecond))
		_ = a.PutConnLog(context.Background(), store.Event{Tunnel: "t", Event: "end"})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		a.Drain(ctx)
		if drops.Load() != 1 {
			t.Errorf("a permanently-failing write must drop exactly once, drops = %d", drops.Load())
		}
		if !strings.Contains(buf.String(), "dropped after retries") {
			t.Errorf("a permanent failure must log a warning; log = %q", buf.String())
		}
	})
}

func TestAsyncConnLog_DrainFlushes(t *testing.T) {
	inner := &countingLog{}
	a := store.NewAsyncConnLog(inner, nil, nil)

	const n = 200
	for range n {
		_ = a.PutConnLog(context.Background(), store.Event{Tunnel: "t"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.Drain(ctx)

	if got := inner.count(); got != n {
		t.Errorf("Drain must flush every queued event, wrote %d of %d", got, n)
	}
	// A post-Drain enqueue is a no-op nil (drops), never a panic on the closed channel.
	if err := a.PutConnLog(context.Background(), store.Event{}); err != nil {
		t.Errorf("post-Drain PutConnLog must return nil, got %v", err)
	}
}
