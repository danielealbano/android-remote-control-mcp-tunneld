package caplog

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newBufLogger() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return newLogger(log, time.Minute, time.Now), &buf
}

func TestCaplogLogsFirstHitImmediately(t *testing.T) {
	l, buf := newBufLogger()
	l.Hit("tunnelA", "rate_rps", "1.1.1.1")
	if n := strings.Count(buf.String(), `msg="cap hit"`); n != 1 {
		t.Errorf("first hit immediate logs = %d, want 1", n)
	}
}

func TestCaplogDedupsWithinWindow(t *testing.T) {
	l, buf := newBufLogger()
	for i := 0; i < 1000; i++ {
		l.Hit("tunnelA", "rate_rps", "1.1.1.1")
	}
	l.Flush()
	if n := strings.Count(buf.String(), `msg="cap hit"`); n != 1 {
		t.Errorf("immediate logs = %d, want exactly 1", n)
	}
	if n := strings.Count(buf.String(), `msg="cap hit summary"`); n != 1 {
		t.Errorf("summary logs = %d, want ≤1 (expected 1)", n)
	}
}

func TestCaplog_IPSetBounded(t *testing.T) {
	l, buf := newBufLogger()
	for i := 0; i < maxTrackedIPs+100; i++ {
		l.Hit("t", "rate_rps", fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}
	l.Flush()
	if want := fmt.Sprintf("ips=%d+", maxTrackedIPs); !strings.Contains(buf.String(), want) {
		t.Errorf("summary must report the capped ip count %q; got: %s", want, buf.String())
	}
}

func TestCaplog_WindowExpiryRelog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	now := time.Unix(0, 0)
	l := newLogger(log, time.Minute, func() time.Time { return now })
	l.Hit("t", "r", "1.1.1.1") // immediate #1
	l.Hit("t", "r", "2.2.2.2") // accumulates in window 1
	now = now.Add(2 * time.Minute)
	l.Hit("t", "r", "3.3.3.3") // crosses the window: emits summary for window 1 + immediate #2
	l.Flush()
	out := buf.String()
	if n := strings.Count(out, `msg="cap hit"`); n != 2 {
		t.Errorf("immediate logs = %d, want 2 (first hit of each window)", n)
	}
	if n := strings.Count(out, `msg="cap hit summary"`); n < 1 {
		t.Errorf("expected a summary across the window boundary; got %d", n)
	}
}

func TestCaplogSummaryCountsHitsAndIPs(t *testing.T) {
	l, buf := newBufLogger()
	l.Hit("t", "r", "1.1.1.1")
	l.Hit("t", "r", "2.2.2.2")
	l.Hit("t", "r", "1.1.1.1")
	l.Flush()
	out := buf.String()
	if !strings.Contains(out, "count=3") {
		t.Errorf("summary count wrong: %s", out)
	}
	if !strings.Contains(out, "ips=2") {
		t.Errorf("summary distinct-ips wrong: %s", out)
	}
}
