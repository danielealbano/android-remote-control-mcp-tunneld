package logging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLogFanoutSplitsBySeverity(t *testing.T) {
	var out, err bytes.Buffer
	logger, closeAll, e := newLogger([]string{"output=std;level=debug"}, &out, &err)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if cerr := closeAll(); cerr != nil {
			t.Errorf("close log sinks: %v", cerr)
		}
	}()

	logger.Info("info-line")
	logger.Warn("warn-line")

	if !strings.Contains(out.String(), "info-line") {
		t.Errorf("info not on stdout: %q", out.String())
	}
	if strings.Contains(out.String(), "warn-line") {
		t.Errorf("warn MUST NOT appear on stdout: %q", out.String())
	}
	if !strings.Contains(err.String(), "warn-line") {
		t.Errorf("warn not on stderr: %q", err.String())
	}
	if strings.Contains(err.String(), "info-line") {
		t.Errorf("info MUST NOT appear on stderr: %q", err.String())
	}
}

func TestLogFanoutWritesFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunneld.log")
	logger, closeAll, e := newLogger([]string{"output=" + path + ";level=info;maxsize=50m;maxfiles=20"}, &bytes.Buffer{}, &bytes.Buffer{})
	if e != nil {
		t.Fatal(e)
	}
	logger.Info("file-sink-line", "k", "v")
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "file-sink-line") {
		t.Errorf("record not in file sink: %q", string(data))
	}
	// Default file format is JSON.
	if !strings.Contains(string(data), `"msg":"file-sink-line"`) {
		t.Errorf("file sink expected JSON format: %q", string(data))
	}
}

func TestLogDefaultWhenEmpty(t *testing.T) {
	var out, err bytes.Buffer
	logger, closeAll, e := newLogger(nil, &out, &err)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if cerr := closeAll(); cerr != nil {
			t.Errorf("close log sinks: %v", cerr)
		}
	}()
	logger.Debug("debug-line") // below info floor → dropped
	logger.Info("info-line")
	if strings.Contains(out.String(), "debug-line") {
		t.Errorf("default level is info; debug MUST be dropped: %q", out.String())
	}
	if !strings.Contains(out.String(), "info-line") {
		t.Errorf("info not emitted at default level: %q", out.String())
	}
}

func TestLogging_FileSinkProbeFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent path is a regular file, so the sink cannot be created → the startup probe must fail.
	bad := filepath.Join(blocker, "x.log")
	_, closeAll, err := newLogger([]string{"output=" + bad + ";level=info"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		if cerr := closeAll(); cerr != nil {
			t.Logf("close the unexpectedly created sink: %v", cerr)
		}
		t.Error("an unwritable file sink must fail at startup")
	}
}

func TestParseSpecs_DuplicateOutput(t *testing.T) {
	for _, spec := range []string{
		"output=std;output=/x.log",
		"output=/x.log;output=std",
	} {
		err := ParseSpecs([]string{spec})
		if err == nil {
			t.Fatalf("ParseSpecs(%q) expected a duplicate-output error", spec)
		}
		if !strings.Contains(err.Error(), spec) {
			t.Errorf("error must name the offending spec %q, got %v", spec, err)
		}
	}
	// A single output= still parses.
	if err := ParseSpecs([]string{"output=/x.log;level=info"}); err != nil {
		t.Errorf("single output= rejected: %v", err)
	}
}

func TestParseSpecsRejectsBad(t *testing.T) {
	for _, spec := range []string{
		"level=info",             // missing output
		"output=std;level=bogus", // bad level
		"output=std;format=yaml", // bad format
		"output=/x;maxsize=abc",  // bad maxsize
		"output=std;unknown=1",   // unknown field
		"badfield",               // not key=value
	} {
		if err := ParseSpecs([]string{spec}); err == nil {
			t.Errorf("ParseSpecs(%q) expected error", spec)
		}
	}
	// Valid specs parse.
	if err := ParseSpecs([]string{"output=std;level=info", "output=/tmp/x.log;maxsize=10m;maxfiles=5"}); err != nil {
		t.Errorf("valid specs rejected: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestFanout_SinkFailureReportedAndCounted(t *testing.T) {
	var report bytes.Buffer
	logger, closeAll, err := newLogger([]string{"output=std;level=info"}, failingWriter{}, &report)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := closeAll(); cerr != nil {
			t.Errorf("close log sinks: %v", cerr)
		}
	}()
	h := logger.Handler().(*fanoutHandler)
	now := time.Unix(1_700_000_000, 0)
	h.health.now = func() time.Time { return now }
	record := slog.NewRecord(now, slog.LevelInfo, "info-line", 0)

	for range 3 {
		if err := h.Handle(context.Background(), record); err == nil || !strings.Contains(err.Error(), "log sink std") {
			t.Fatalf("Handle = %v, want the failing sink's error", err)
		}
	}
	if got := strings.Count(report.String(), "tunneld: log sink std failed: disk full"); got != 1 {
		t.Fatalf("reports within a minute = %d, want 1 (rate-limited); report = %q", got, report.String())
	}
	now = now.Add(sinkReportEvery + time.Second)
	if err := h.Handle(context.Background(), record); err == nil {
		t.Fatal("Handle must keep returning the sink error")
	}
	if !strings.Contains(report.String(), "(2 more failures since the last report)") {
		t.Fatalf("the next report must carry the suppressed count; report = %q", report.String())
	}
	if got := h.SinkErrors(); got != 4 {
		t.Fatalf("SinkErrors = %d, want 4", got)
	}
}

func TestFanout_UnwritableReportRetried(t *testing.T) {
	logger, closeAll, err := newLogger([]string{"output=std;level=info"}, failingWriter{}, failingWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := closeAll(); cerr != nil {
			t.Errorf("close log sinks: %v", cerr)
		}
	}()
	h := logger.Handler().(*fanoutHandler)
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "info-line", 0)
	for range 2 {
		if err := h.Handle(context.Background(), record); err == nil {
			t.Fatal("Handle must return the sink error")
		}
	}
	st := h.health.status["std"]
	if st == nil || !st.lastReport.IsZero() || st.suppressed != 2 {
		t.Fatalf("an unwritable report must stay pending and count the failures, got %+v", st)
	}
}

type toggleWriter struct {
	failing atomic.Bool
}

func (w *toggleWriter) Write(p []byte) (int, error) {
	if w.failing.Load() {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestFanout_SinkSummaryAfterFailuresStop(t *testing.T) {
	tests := []struct {
		name  string
		flush func(t *testing.T, h *fanoutHandler, closeAll func() error, now *time.Time)
	}{
		{name: "next record after the window", flush: func(t *testing.T, h *fanoutHandler, closeAll func() error, now *time.Time) {
			*now = now.Add(sinkReportEvery + time.Second)
			if err := h.Handle(context.Background(), slog.NewRecord(*now, slog.LevelInfo, "recovered", 0)); err != nil {
				t.Fatalf("a recovered sink must accept records, got %v", err)
			}
			t.Cleanup(func() {
				if err := closeAll(); err != nil {
					t.Errorf("close log sinks: %v", err)
				}
			})
		}},
		{name: "close", flush: func(t *testing.T, _ *fanoutHandler, closeAll func() error, _ *time.Time) {
			if err := closeAll(); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var report bytes.Buffer
			out := &toggleWriter{}
			logger, closeAll, err := newLogger([]string{"output=std;level=info"}, out, &report)
			if err != nil {
				t.Fatal(err)
			}
			h := logger.Handler().(*fanoutHandler)
			now := time.Unix(1_700_000_000, 0)
			h.health.now = func() time.Time { return now }
			out.failing.Store(true)
			for range 3 {
				if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelInfo, "info-line", 0)); err == nil {
					t.Fatal("Handle must return the sink error while it fails")
				}
			}
			out.failing.Store(false)
			tc.flush(t, h, closeAll, &now)
			if !strings.Contains(report.String(), "tunneld: log sink std: 2 failures since the last report") {
				t.Fatalf("the suppressed failures must be reported once failures stop; report = %q", report.String())
			}
		})
	}
}
