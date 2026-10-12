package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// captureWarn returns a logger writing Warn+Error records into the returned buffer. slog serializes
// concurrent handler writes, so worker goroutines may log into it safely; read it only after Drain.
func captureWarn() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// blockingLog blocks every PutConnLogBatch until release is closed (a stalled inner store).
type blockingLog struct {
	release chan struct{}
	writes  atomic.Int64
}

func (b *blockingLog) PutConnLogBatch(_ context.Context, batch store.ConnLogBatch) error {
	<-b.release
	b.writes.Add(int64(len(batch.Events)))
	return nil
}

type recordingLog struct {
	mu      sync.Mutex
	batches []store.ConnLogBatch
}

func (r *recordingLog) PutConnLogBatch(_ context.Context, batch store.ConnLogBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, batch)
	return nil
}

func (r *recordingLog) snapshot() []store.ConnLogBatch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.batches)
}

// flakyLog fails the first failFirst attempts (across all events), then succeeds.
type flakyLog struct {
	failFirst int64
	attempts  atomic.Int64
	writes    atomic.Int64
}

func (f *flakyLog) PutConnLogBatch(_ context.Context, batch store.ConnLogBatch) error {
	if f.attempts.Add(1) <= f.failFirst {
		return errors.New("inject: conn-log write failed")
	}
	f.writes.Add(int64(len(batch.Events)))
	return nil
}

var day1 = time.Date(2026, 8, 17, 23, 59, 0, 0, time.UTC)

func startEvent(tunnel string, at time.Time) store.Event {
	return store.Event{Event: "start", Tunnel: tunnel, TSStart: at}
}

func drain(t *testing.T, a *store.AsyncConnLog) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a.Drain(ctx)
}

func enqueue(t *testing.T, a *store.AsyncConnLog, evs ...store.Event) {
	t.Helper()
	for _, ev := range evs {
		if err := a.PutConnLog(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
}

func waitBatches(t *testing.T, r *recordingLog, n int) []store.ConnLogBatch {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b := r.snapshot(); len(b) >= n {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d written batches, got %d", n, len(r.snapshot()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAsyncConnLog_EnqueueNonBlocking(t *testing.T) {
	release := make(chan struct{})
	inner := &blockingLog{release: release}
	a := store.NewAsyncConnLog(inner, "n1", nil, nil)

	done := make(chan struct{})
	go func() {
		for range 101 {
			if err := a.PutConnLog(context.Background(), startEvent("t", day1)); err != nil {
				tunneltest.Logger().Warn("enqueue failed", "err", err)
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PutConnLog must not block even when the inner store stalls")
	}

	close(release)
	drain(t, a)
}

func TestAsyncConnLog_FullBufferDropsNewest(t *testing.T) {
	block := make(chan struct{})
	inner := &blockingLog{release: block} // stays blocked → workers stall, the buffer fills
	var drops atomic.Int64
	a := store.NewAsyncConnLog(inner, "n1", func(n int) { drops.Add(int64(n)) }, nil)

	for range 5000 + 10 {
		enqueue(t, a, startEvent("t", day1))
	}
	if got := drops.Load(); got != 10 {
		t.Fatalf("a full buffer must drop exactly the events past 5000, drops = %d", got)
	}

	close(block)
	drain(t, a)
	if got := inner.writes.Load(); got != 5000 {
		t.Fatalf("every accepted event must be written, wrote %d", got)
	}
}

func TestAsyncConnLog_CountTrigger(t *testing.T) {
	inner := &recordingLog{}
	a := store.NewAsyncConnLog(inner, "n1", nil, nil)
	for i := range 100 {
		enqueue(t, a, startEvent("t", day1.Add(time.Duration(i))))
	}
	b := waitBatches(t, inner, 1)
	if len(b) != 1 || len(b[0].Events) != 100 || !b[0].First.Equal(day1) || b[0].NodeID != "n1" {
		t.Fatalf("100 events must be written as one batch before the age trigger, got %+v", b)
	}
	drain(t, a)
}

func TestAsyncConnLog_AgeTrigger(t *testing.T) {
	var clock atomic.Int64
	clock.Store(day1.UnixNano())
	inner := &recordingLog{}
	a := store.NewAsyncConnLog(inner, "n1", nil, nil,
		store.WithClock(func() time.Time { return time.Unix(0, clock.Load()) }),
		store.WithAgeCheck(time.Millisecond))
	enqueue(t, a, startEvent("t", day1), startEvent("t", day1), startEvent("t", day1))

	clock.Add(int64(5*time.Minute - time.Nanosecond))
	time.Sleep(50 * time.Millisecond)
	if got := len(inner.snapshot()); got != 0 {
		t.Fatalf("a batch younger than 5 minutes must not be written, got %d batches", got)
	}
	clock.Add(int64(time.Nanosecond))
	if b := waitBatches(t, inner, 1); len(b[0].Events) != 3 {
		t.Fatalf("the aged batch must carry its 3 events, got %+v", b)
	}
	drain(t, a)
}

func TestAsyncConnLog_SplitsByTunnelAndDay(t *testing.T) {
	inner := &recordingLog{}
	a := store.NewAsyncConnLog(inner, "n1", nil, nil)
	day2 := day1.Add(2 * time.Minute)
	end := store.Event{Event: "end", Tunnel: "a", TSStart: day1, TSEnd: day2}
	enqueue(t, a, startEvent("a", day1), startEvent("b", day1), startEvent("a", day1.Add(time.Second)), end)
	drain(t, a)

	got := map[string]int{}
	for _, b := range inner.snapshot() {
		got[b.Key()] = len(b.Events)
	}
	want := map[string]int{
		"tunnel-logs/a/2026/08/17/20260817T235900.000000000Z-n1.jsonl": 2,
		"tunnel-logs/b/2026/08/17/20260817T235900.000000000Z-n1.jsonl": 1,
		"tunnel-logs/a/2026/08/18/20260818T000100.000000000Z-n1.jsonl": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("batches = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("batches = %v, want %v", got, want)
		}
	}
}

func TestAsyncConnLog_DrainFlushesAndRefusesLateEvents(t *testing.T) {
	inner := &recordingLog{}
	var drops atomic.Int64
	a := store.NewAsyncConnLog(inner, "n1", func(n int) { drops.Add(int64(n)) }, nil)
	for range 250 {
		enqueue(t, a, startEvent("t", day1))
	}
	drain(t, a)

	total := 0
	for _, b := range inner.snapshot() {
		total += len(b.Events)
	}
	if total != 250 {
		t.Fatalf("Drain must flush every buffered event, wrote %d of 250", total)
	}
	// A post-Drain enqueue is a no-op nil (drops), never a panic on the closed channel.
	enqueue(t, a, startEvent("t", day1))
	if drops.Load() != 1 {
		t.Fatalf("a post-Drain event must be counted as dropped, drops = %d", drops.Load())
	}
}

func TestAsyncConnLog_Retries(t *testing.T) {
	t.Run("retries then succeeds", func(t *testing.T) {
		t.Parallel()
		inner := &flakyLog{failFirst: 1} // fail attempt 0, succeed attempt 1 (one backoff)
		var drops atomic.Int64
		a := store.NewAsyncConnLog(inner, "n1", func(n int) { drops.Add(int64(n)) }, nil, store.WithBackoffBase(time.Millisecond))
		enqueue(t, a, startEvent("t", day1), startEvent("t", day1))
		drain(t, a)
		if drops.Load() != 0 {
			t.Errorf("a write that succeeds on retry must not drop, drops = %d", drops.Load())
		}
		if got := inner.writes.Load(); got != 2 {
			t.Errorf("both events must be written on the successful retry, got %d", got)
		}
		if got := inner.attempts.Load(); got != 2 {
			t.Errorf("expected 2 attempts (one failure then success), got %d", got)
		}
	})

	t.Run("retries exhausted drops the batch", func(t *testing.T) {
		t.Parallel()
		inner := &flakyLog{failFirst: 1 << 30} // always fail: all 5 attempts (tiny backoff → milliseconds)
		var drops atomic.Int64
		log, buf := captureWarn()
		a := store.NewAsyncConnLog(inner, "n1", func(n int) { drops.Add(int64(n)) }, log, store.WithBackoffBase(time.Millisecond))
		enqueue(t, a, startEvent("t", day1), startEvent("t", day1), startEvent("t", day1))
		drain(t, a)
		if got := inner.attempts.Load(); got != 5 {
			t.Errorf("a failing batch must be attempted 5 times, got %d", got)
		}
		if drops.Load() != 3 {
			t.Errorf("a dropped batch must count every event it carried, drops = %d", drops.Load())
		}
		want := `msg="conn-log batch dropped after retries" tunnel=t day=2026-08-17 node=n1 events=3 err="inject: conn-log write failed"`
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the dropped batch must be logged with its identifiers and error; log = %q", buf.String())
		}
	})
}
