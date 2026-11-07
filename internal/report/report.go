package report

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	sentryslog "github.com/getsentry/sentry-go/slog"
)

const (
	flushTimeout = 2 * time.Second
	closeTimeout = 3 * time.Second
	eventIDKey   = "sentry_event_id"

	recoveredMsg = "recovered from a crash; only the affected work was stopped"
	crashedMsg   = "a crash could not be contained; tunneld stops so it can be restarted"
	maxTagLength = 200
)

var (
	ErrPanicked = errors.New("report: the operation panicked")

	internalErrorBody = []byte(`{"reason":"internal_error","retryable":true}` + "\n")
)

type Config struct {
	DSN              string
	Environment      string
	Release          string
	ServerName       string
	Node             string
	TracesSampleRate float64
}

type options struct {
	transport sentry.Transport
}

type Option func(*options) error

func WithTransport(t sentry.Transport) Option {
	return func(o *options) error {
		if t == nil {
			return errors.New("report: transport must not be nil")
		}
		o.transport = t
		return nil
	}
}

type Reporter struct {
	hub *sentry.Hub
}

func New(cfg Config, opts ...Option) (*Reporter, error) {
	var o options
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if cfg.DSN == "" {
		return &Reporter{}, nil
	}
	if !(cfg.TracesSampleRate >= 0 && cfg.TracesSampleRate <= 1) {
		return nil, fmt.Errorf("report: traces sample rate must be within [0, 1], got %v", cfg.TracesSampleRate)
	}
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:              cfg.DSN,
		Environment:      cfg.Environment,
		Release:          cfg.Release,
		ServerName:       cfg.ServerName,
		Tags:             map[string]string{"node": cfg.Node},
		EnableTracing:    cfg.TracesSampleRate > 0,
		TracesSampleRate: cfg.TracesSampleRate,
		AttachStacktrace: true,
		Transport:        o.transport,
	})
	if err != nil {
		return nil, fmt.Errorf("report: sentry client: %w", err)
	}
	return &Reporter{hub: sentry.NewHub(client, sentry.NewScope())}, nil
}

func CheckDSN(dsn string) error {
	if _, err := sentry.NewDsn(dsn); err != nil {
		return fmt.Errorf("report: parse the sentry dsn: %w", err)
	}
	return nil
}

func (r *Reporter) Enabled() bool { return r.hub != nil }

func (r *Reporter) Context(ctx context.Context) context.Context {
	if r.hub == nil {
		return ctx
	}
	return sentry.SetHubOnContext(ctx, r.hub)
}

func (r *Reporter) Logger(base *slog.Logger) *slog.Logger {
	if r.hub == nil {
		return base
	}
	logs := sentryslog.Option{
		LogLevel: []slog.Level{slog.LevelWarn, slog.LevelError, sentryslog.LevelFatal},
	}.NewSentryHandler(r.Context(context.Background()))
	return slog.New(&teeHandler{base: base.Handler(), logs: logs, hub: r.hub})
}

func (r *Reporter) Flush(ctx context.Context) bool {
	if r.hub == nil {
		return true
	}
	return flush(ctx, r.hub)
}

func flush(ctx context.Context, hub *sentry.Hub) bool {
	fctx, cancel := context.WithTimeout(ctx, flushTimeout)
	defer cancel()
	return hub.FlushWithContext(fctx)
}

func (r *Reporter) Close(ctx context.Context, logger *slog.Logger) bool {
	if r.hub == nil {
		return true
	}
	flushed := flush(ctx, r.hub)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		defer Recover(ctx, logger, "sentry close", func() {})
		r.hub.Client().Close()
	}()
	cctx, cancel := context.WithTimeout(ctx, closeTimeout)
	defer cancel()
	select {
	case <-closed:
		return flushed
	case <-cctx.Done():
		return false
	}
}

func (r *Reporter) Handler(next http.Handler, logger *slog.Logger, what string, trace func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := WithScope(r.Context(req.Context()))
		tw := &trackingWriter{ResponseWriter: w}
		panicked := false
		if hub := sentry.GetHubFromContext(ctx); hub != nil {
			bodyless := *req
			bodyless.Body = http.NoBody
			hub.Scope().SetRequest(&bodyless)
			if trace(req) {
				tx := sentry.StartTransaction(ctx, req.Method+" "+req.URL.Path,
					sentry.WithOpName("http.server"), sentry.WithTransactionSource(sentry.SourceURL))
				defer func() {
					if refused(ctx) && !panicked {
						return
					}
					status := tw.statusCode()
					tx.Status = sentry.HTTPtoSpanStatus(status)
					tx.SetData("http.response.status_code", status)
					tx.Finish()
				}()
				ctx = tx.Context()
			}
		}
		SetAttrs(ctx, clientAttrs(req.RemoteAddr)...)
		req = req.WithContext(ctx)
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			aborted := false
			if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				aborted = true
			} else {
				panicked = true
				handlePanic(ctx, logger, what, v, recoveredMsg)
			}
			if tw.hijacked != nil {
				if err := tw.hijacked.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					logger.DebugContext(ctx, "could not close a taken-over connection cleanly after a crash; it is not used again", "where", what, "err", err)
				}
			}
			if aborted {
				panic(v)
			}
			if tw.wrote {
				panic(http.ErrAbortHandler)
			}
			tw.Header().Set("Content-Type", "application/json")
			tw.WriteHeader(http.StatusInternalServerError)
			if _, err := tw.Write(internalErrorBody); err != nil {
				logger.DebugContext(ctx, "could not send the error answer after a crash; the client may get an incomplete answer or none", "where", what, "err", err)
			}
		}()
		next.ServeHTTP(tw, req)
	})
}

func GetCertificate(ctx context.Context, logger *slog.Logger, what string,
	get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
		cctx := WithScope(ctx)
		defer Recover(cctx, logger, what, func() { cert, err = nil, ErrPanicked })
		if hello.Conn != nil {
			SetAttrs(cctx, clientAttrs(hello.Conn.RemoteAddr().String())...)
		}
		SetAttrs(cctx, slog.String("sni", hello.ServerName))
		return get(hello)
	}
}

func GetClientCertificate(ctx context.Context, logger *slog.Logger, what string,
	get func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (cert *tls.Certificate, err error) {
		defer Recover(ctx, logger, what, func() { cert, err = nil, ErrPanicked })
		return get(info)
	}
}

func VerifyConnection(ctx context.Context, logger *slog.Logger, what string,
	verify func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) (err error) {
		defer Recover(ctx, logger, what, func() { err = ErrPanicked })
		return verify(cs)
	}
}

func Recover(ctx context.Context, logger *slog.Logger, what string, onPanic func()) {
	v := recover()
	if v == nil {
		return
	}
	handlePanic(ctx, logger, what, v, recoveredMsg)
	onPanic()
}

func RecoverWith(ctx context.Context, logger *slog.Logger, what, msg string, onPanic func()) {
	v := recover()
	if v == nil {
		return
	}
	handlePanic(ctx, logger, what, v, msg)
	onPanic()
}

func Crash(ctx context.Context, logger *slog.Logger, what string) {
	v := recover()
	if v == nil {
		return
	}
	handlePanic(ctx, logger, what, v, crashedMsg)
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		flush(context.WithoutCancel(ctx), hub)
	}
	panic(v)
}

func handlePanic(ctx context.Context, logger *slog.Logger, what string, v any, msg string) {
	var eventID string
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		h := hub.Clone()
		h.Scope().SetTag("where", what)
		if id := h.RecoverWithContext(ctx, panicError(v)); id != nil {
			eventID = string(*id)
		}
	}
	attrs := []any{"where", what, "panic", fmt.Sprint(v), "stack", string(debug.Stack())}
	for _, a := range scopeAttrs(ctx) {
		attrs = append(attrs, a)
	}
	if eventID != "" {
		attrs = append(attrs, eventIDKey, eventID)
	}
	logger.ErrorContext(ctx, msg, attrs...)
}

func panicError(v any) error {
	if err, ok := v.(error); ok {
		return err
	}
	return fmt.Errorf("panic: %v", v)
}

func CaptureError(ctx context.Context, err error, attrs ...slog.Attr) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		return
	}
	h := hub.Clone()
	setTags(h.Scope(), attrs)
	h.CaptureException(err)
}

type scopeKey struct{}

type scope struct {
	mu      sync.Mutex
	attrs   []slog.Attr
	refused bool
}

func WithScope(ctx context.Context) context.Context {
	s := &scope{attrs: scopeAttrs(ctx)}
	ctx = context.WithValue(ctx, scopeKey{}, s)
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		h := hub.Clone()
		h.Scope().SetPropagationContext(sentry.NewPropagationContext())
		ctx = sentry.SetHubOnContext(ctx, h)
	}
	return ctx
}

func SetAttrs(ctx context.Context, attrs ...slog.Attr) {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return
	}
	s.mu.Lock()
	for _, a := range attrs {
		replaced := false
		for i := range s.attrs {
			if s.attrs[i].Key == a.Key {
				s.attrs[i] = a
				replaced = true
				break
			}
		}
		if !replaced {
			s.attrs = append(s.attrs, a)
		}
	}
	s.mu.Unlock()
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		setTags(hub.Scope(), attrs)
	}
}

func Refuse(ctx context.Context) {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return
	}
	s.mu.Lock()
	s.refused = true
	s.mu.Unlock()
}

func refused(ctx context.Context) bool {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

func scopeAttrs(ctx context.Context) []slog.Attr {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]slog.Attr(nil), s.attrs...)
}

func ClientAttrs(remoteAddr string) []slog.Attr { return clientAttrs(remoteAddr) }

func clientAttrs(remoteAddr string) []slog.Attr {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return []slog.Attr{slog.String("client_ip", remoteAddr)}
	}
	return []slog.Attr{slog.String("client_ip", host), slog.String("client_port", port)}
}

func setTags(scope *sentry.Scope, attrs []slog.Attr) {
	for _, a := range attrs {
		if s := a.Value.String(); len(s) <= maxTagLength {
			scope.SetTag(a.Key, s)
		}
	}
}

type Span struct {
	span *sentry.Span
}

func StartSpan(ctx context.Context, op, name string) (context.Context, Span) {
	if sentry.GetHubFromContext(ctx) == nil {
		return ctx, Span{}
	}
	s := sentry.StartTransaction(ctx, name, sentry.WithOpName(op), sentry.WithTransactionSource(sentry.SourceCustom))
	return s.Context(), Span{span: s}
}

func (s Span) SetAttrs(attrs ...slog.Attr) {
	if s.span == nil {
		return
	}
	for _, a := range attrs {
		if v := a.Value.String(); len(v) <= maxTagLength {
			s.span.SetTag(a.Key, v)
		}
		s.span.SetData(a.Key, a.Value.Any())
	}
}

func (s Span) Finish() {
	if s.span != nil {
		s.span.Finish()
	}
}

type trackingWriter struct {
	http.ResponseWriter
	wrote    bool
	status   int
	hijacked net.Conn
}

func (t *trackingWriter) WriteHeader(code int) {
	if !t.wrote {
		t.status = code
	}
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	if !t.wrote {
		t.status = http.StatusOK
	}
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackingWriter) statusCode() int {
	if t.status == 0 {
		return http.StatusOK
	}
	return t.status
}

func (t *trackingWriter) Flush() {
	if !t.wrote {
		t.status = http.StatusOK
	}
	t.wrote = true
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (t *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(t.ResponseWriter).Hijack()
	if err == nil {
		t.wrote = true
		t.hijacked = conn
	}
	return conn, brw, err
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }
