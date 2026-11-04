package report

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/getsentry/sentry-go"
)

type teeHandler struct {
	base   slog.Handler
	logs   slog.Handler
	hub    *sentry.Hub
	attrs  []slog.Attr
	groups []string
}

func (h *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level) || h.logs.Enabled(ctx, level)
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	if h.base.Enabled(ctx, r.Level) {
		errs = append(errs, h.base.Handle(ctx, r))
	}
	if h.logs.Enabled(ctx, r.Level) {
		errs = append(errs, h.logs.Handle(ctx, r.Clone()))
	}
	if r.Level >= slog.LevelError {
		h.capture(ctx, r)
	}
	return errors.Join(errs...)
}

func (h *teeHandler) capture(ctx context.Context, r slog.Record) {
	fields := map[string]any{}
	tags := map[string]string{}
	var add func(key string, v slog.Value)
	add = func(key string, v slog.Value) {
		v = v.Resolve()
		if v.Kind() == slog.KindGroup {
			for _, a := range v.Group() {
				child := a.Key
				if key != "" {
					child = key + "." + a.Key
				}
				add(child, a.Value)
			}
			return
		}
		switch v.Kind() {
		case slog.KindString, slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool:
			fields[key] = v.Any()
		default:
			fields[key] = v.String()
		}
		if s := v.String(); len(s) <= maxTagLength {
			tags[key] = s
		}
	}
	for _, a := range h.attrs {
		add(a.Key, a.Value)
	}
	prefix := groupPrefix(h.groups)
	skip := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == eventIDKey {
			skip = true
			return false
		}
		add(prefix+a.Key, a.Value)
		return true
	})
	if skip {
		return
	}
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = h.hub
	}
	event := sentry.NewEvent()
	event.Level = sentry.LevelError
	event.Message = r.Message
	event.Tags = tags
	event.Contexts = map[string]sentry.Context{"log": fields}
	hub.CaptureEvent(event)
}

func (h *teeHandler) Unwrap() slog.Handler { return h.base }

func groupPrefix(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return strings.Join(groups, ".") + "."
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	c := *h
	c.base = h.base.WithAttrs(attrs)
	c.logs = h.logs.WithAttrs(attrs)
	prefix := groupPrefix(h.groups)
	c.attrs = append([]slog.Attr{}, h.attrs...)
	for _, a := range attrs {
		c.attrs = append(c.attrs, slog.Attr{Key: prefix + a.Key, Value: a.Value})
	}
	return &c
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.base = h.base.WithGroup(name)
	c.logs = h.logs.WithGroup(name)
	c.groups = append(append([]string{}, h.groups...), name)
	return &c
}
