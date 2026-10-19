package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const sinkReportEvery = time.Minute

type sink struct {
	name string
	h    slog.Handler
}

type sinkHealth struct {
	report  io.Writer
	now     func() time.Time
	errs    atomic.Uint64
	pending atomic.Bool

	mu     sync.Mutex
	status map[string]*sinkStatus
}

type sinkStatus struct {
	lastReport time.Time
	suppressed uint64
}

func newSinkHealth(report io.Writer) *sinkHealth {
	return &sinkHealth{report: report, now: time.Now, status: map[string]*sinkStatus{}}
}

func (s *sinkHealth) failed(name string, err error) {
	s.errs.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[name]
	if st == nil {
		st = &sinkStatus{}
		s.status[name] = st
	}
	now := s.now()
	if !st.lastReport.IsZero() && now.Sub(st.lastReport) < sinkReportEvery {
		st.suppressed++
		s.pending.Store(true)
		return
	}
	if _, werr := fmt.Fprintf(s.report, "tunneld: log sink %s failed: %v (%d more failures since the last report)\n", name, err, st.suppressed); werr != nil {
		st.suppressed++
		s.pending.Store(true)
		return
	}
	st.lastReport, st.suppressed = now, 0
}

func (s *sinkHealth) sweep(force bool) {
	if !s.pending.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	still := false
	for name, st := range s.status {
		if st.suppressed == 0 {
			continue
		}
		if !force && !st.lastReport.IsZero() && now.Sub(st.lastReport) < sinkReportEvery {
			still = true
			continue
		}
		if _, err := fmt.Fprintf(s.report, "tunneld: log sink %s: %d failures since the last report\n", name, st.suppressed); err != nil {
			still = true
			continue
		}
		st.lastReport, st.suppressed = now, 0
	}
	s.pending.Store(still)
}

// fanoutHandler dispatches each record to every child that admits its level. Enabled reports true
// if ANY child would handle the record, so slog does not drop records the fan-out still needs.
type fanoutHandler struct {
	children []sink
	health   *sinkHealth
}

func (h *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, c := range h.children {
		if c.h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, c := range h.children {
		if !c.h.Enabled(ctx, r.Level) {
			continue
		}
		if err := c.h.Handle(ctx, r.Clone()); err != nil {
			h.health.failed(c.name, err)
			errs = append(errs, fmt.Errorf("log sink %s: %w", c.name, err))
		}
	}
	h.health.sweep(false)
	return errors.Join(errs...)
}

func (h *fanoutHandler) SinkErrors() uint64 { return h.health.errs.Load() }

func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]sink, len(h.children))
	for i, c := range h.children {
		next[i] = sink{name: c.name, h: c.h.WithAttrs(attrs)}
	}
	return &fanoutHandler{children: next, health: h.health}
}

func (h *fanoutHandler) WithGroup(name string) slog.Handler {
	next := make([]sink, len(h.children))
	for i, c := range h.children {
		next[i] = sink{name: c.name, h: c.h.WithGroup(name)}
	}
	return &fanoutHandler{children: next, health: h.health}
}

// stdSplitHandler is a std sink: it routes each admitted record to EXACTLY one of two underlying
// handlers by severity — level < warn → stdout, level >= warn → stderr. A warn/error record never
// reaches stdout and an info/debug record never reaches stderr.
type stdSplitHandler struct {
	out slog.Handler // os.Stdout (or injected buffer)
	err slog.Handler // os.Stderr (or injected buffer)
}

func newStdSplit(stdout, stderr io.Writer, s spec) slog.Handler {
	return &stdSplitHandler{
		out: newHandler(stdout, s),
		err: newHandler(stderr, s),
	}
}

func (h *stdSplitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// out and err share the same level floor; either answers.
	return h.out.Enabled(ctx, level)
}

func (h *stdSplitHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		return h.err.Handle(ctx, r)
	}
	return h.out.Handle(ctx, r)
}

func (h *stdSplitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stdSplitHandler{out: h.out.WithAttrs(attrs), err: h.err.WithAttrs(attrs)}
}

func (h *stdSplitHandler) WithGroup(name string) slog.Handler {
	return &stdSplitHandler{out: h.out.WithGroup(name), err: h.err.WithGroup(name)}
}

// newLeaf builds a single min-level handler (used for file sinks over a lumberjack writer).
func newLeaf(w io.Writer, s spec) slog.Handler {
	return newHandler(w, s)
}
