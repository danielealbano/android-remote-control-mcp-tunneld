package soak

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	maxResponse = 65536
	maxRequest  = 1 << 20
	maxBackoff  = 16 * time.Second
	maxFailures = 1000
)

var nameRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

var errNoTunnelWorks = errors.New("every tunnel keeps failing")

type config struct {
	namesFile string
	domain    string
	interval  time.Duration
	reqBytes  int
	respBytes int
	reconnect time.Duration
	duration  time.Duration
	timeout   time.Duration
	out       string
	caFile    string
	connect   string
	ramp      time.Duration
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("soak-client", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.namesFile, "names-file", "", "file with one tunnel name per line (required)")
	fs.StringVar(&c.domain, "domain", "", "tunnel domain (required)")
	fs.DurationVar(&c.interval, "interval", time.Second, "time between operations per phone")
	fs.IntVar(&c.reqBytes, "req-bytes", 1024, "average request body size in bytes")
	fs.IntVar(&c.respBytes, "resp-bytes", 5120, "average response body size in bytes")
	fs.DurationVar(&c.reconnect, "reconnect", 5*time.Minute, "drop and re-open each phone's connection this often")
	fs.DurationVar(&c.duration, "duration", 24*time.Hour, "total run time")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-operation timeout")
	fs.StringVar(&c.out, "out", "soak.csv", "per-minute CSV output file")
	fs.StringVar(&c.caFile, "ca-file", "", "PEM roots to trust instead of the system roots")
	fs.StringVar(&c.connect, "connect", "", "host:port to dial for every phone instead of resolving its name")
	fs.DurationVar(&c.ramp, "ramp", 0, "spread the phones' first operations (and so their reconnects) evenly over this long")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	switch {
	case c.namesFile == "":
		return config{}, errors.New("--names-file is required")
	case c.domain == "":
		return config{}, errors.New("--domain is required")
	case c.interval <= 0 || c.reconnect <= 0 || c.duration <= 0 || c.timeout <= 0:
		return config{}, errors.New("--interval, --reconnect, --duration and --timeout must be positive")
	case c.ramp < 0:
		return config{}, errors.New("--ramp must not be negative")
	case c.reqBytes <= 0 || c.respBytes <= 0:
		return config{}, errors.New("--req-bytes and --resp-bytes must be positive")
	case maxSize(c.respBytes) > maxResponse:
		return config{}, fmt.Errorf("--resp-bytes %d: responses up to %d bytes exceed the phone's %d-byte limit", c.respBytes, maxSize(c.respBytes), maxResponse)
	case maxSize(c.reqBytes) > maxRequest:
		return config{}, fmt.Errorf("--req-bytes %d: requests up to %d bytes exceed the phone's %d-byte limit", c.reqBytes, maxSize(c.reqBytes), maxRequest)
	}
	if c.connect != "" {
		if _, _, err := net.SplitHostPort(c.connect); err != nil {
			return config{}, fmt.Errorf("--connect %q: %w", c.connect, err)
		}
	}
	return c, nil
}

func readNames(r io.Reader) ([]string, error) {
	var names []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		n := strings.TrimSpace(sc.Text())
		if n == "" {
			continue
		}
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("invalid tunnel name %q", n)
		}
		names = append(names, n)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read names: %w", err)
	}
	if len(names) == 0 {
		return nil, errors.New("no tunnel names")
	}
	return names, nil
}

func minSize(avg int) int { return max(1, avg/5) }
func maxSize(avg int) int { return avg * 9 / 5 }

func sizeAround(avg int) (int, error) {
	lo, hi := minSize(avg), maxSize(avg)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, fmt.Errorf("random size: %w", err)
	}
	return lo + int(n.Int64()), nil
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func verify(b []byte, n int) error {
	if len(b) != n {
		return fmt.Errorf("response is %d bytes, want %d", len(b), n)
	}
	for i, v := range b {
		if v != byte(i%251) {
			return fmt.Errorf("response byte %d is %d, want %d", i, v, byte(i%251))
		}
	}
	return nil
}

func classify(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	var opErr *net.OpError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certErr), errors.As(err, &recErr):
		return "tls"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "dial"
	default:
		return "transport"
	}
}

type stats struct {
	ok, errors       int
	kinds            map[string]int
	latencies        []time.Duration
	newConns         int
	bytesUp, bytesDn int64
}

func newStats() *stats { return &stats{kinds: map[string]int{}} }

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted))*p/100+0.999999) - 1
	return sorted[min(max(idx, 0), len(sorted)-1)]
}

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 1, 64)
}

type recorder struct {
	mu          sync.Mutex
	csv         *csv.Writer
	logger      *slog.Logger
	phones      []string
	window      map[string]*stats
	total       map[string]*stats
	logged      map[string]bool
	windowStart time.Time
}

var csvHeader = []string{"minute", "phone", "ok", "errors", "error_kinds", "p50_ms", "p95_ms", "p99_ms", "max_ms", "new_conns", "bytes_up", "bytes_down"}

func newRecorder(w io.Writer, phones []string, start time.Time, logger *slog.Logger) (*recorder, error) {
	r := &recorder{
		csv: csv.NewWriter(w), logger: logger, phones: phones,
		window: map[string]*stats{}, total: map[string]*stats{}, logged: map[string]bool{}, windowStart: start,
	}
	for _, p := range phones {
		r.window[p], r.total[p] = newStats(), newStats()
	}
	if err := r.csv.Write(csvHeader); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}
	r.csv.Flush()
	if err := r.csv.Error(); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}
	return r, nil
}

func (r *recorder) success(phone string, lat time.Duration, up, down int, newConn bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range []*stats{r.window[phone], r.total[phone]} {
		s.ok++
		s.latencies = append(s.latencies, lat)
		s.bytesUp += int64(up)
		s.bytesDn += int64(down)
		if newConn {
			s.newConns++
		}
	}
}

func (r *recorder) failure(phone, kind string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range []*stats{r.window[phone], r.total[phone]} {
		s.errors++
		s.kinds[kind]++
	}
	if key := phone + "|" + kind; !r.logged[key] {
		r.logged[key] = true
		r.logger.Warn("operation failed (first of its kind this minute)", "phone", phone, "kind", kind, "err", err)
	}
}

func kindsField(kinds map[string]int) string {
	keys := make([]string, 0, len(kinds))
	for k := range kinds {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(kinds[k]))
	}
	return strings.Join(parts, ";")
}

func (r *recorder) flush(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	minute := r.windowStart.UTC().Format(time.RFC3339)
	for _, p := range r.phones {
		s := r.window[p]
		lat := slices.Clone(s.latencies)
		slices.Sort(lat)
		var maxLat time.Duration
		if len(lat) > 0 {
			maxLat = lat[len(lat)-1]
		}
		row := []string{
			minute, p, strconv.Itoa(s.ok), strconv.Itoa(s.errors), kindsField(s.kinds),
			ms(percentile(lat, 50)), ms(percentile(lat, 95)), ms(percentile(lat, 99)), ms(maxLat),
			strconv.Itoa(s.newConns), strconv.FormatInt(s.bytesUp, 10), strconv.FormatInt(s.bytesDn, 10),
		}
		if err := r.csv.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
		r.window[p] = newStats()
	}
	r.csv.Flush()
	r.logged = map[string]bool{}
	r.windowStart = now
	if err := r.csv.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	return nil
}

func (r *recorder) summary(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := newStats()
	lines := make([]string, 0, len(r.phones)+1)
	line := func(label string, s *stats) string {
		lat := slices.Clone(s.latencies)
		slices.Sort(lat)
		rate := 0.0
		if n := s.ok + s.errors; n > 0 {
			rate = 100 * float64(s.ok) / float64(n)
		}
		return fmt.Sprintf("%-14s ok=%d errors=%d success=%.3f%% p50=%sms p99=%sms new_conns=%d up=%d down=%d errors_by_kind=[%s]",
			label, s.ok, s.errors, rate, ms(percentile(lat, 50)), ms(percentile(lat, 99)), s.newConns, s.bytesUp, s.bytesDn, kindsField(s.kinds))
	}
	for _, p := range r.phones {
		s := r.total[p]
		lines = append(lines, line(p, s))
		all.ok += s.ok
		all.errors += s.errors
		all.latencies = append(all.latencies, s.latencies...)
		all.newConns += s.newConns
		all.bytesUp += s.bytesUp
		all.bytesDn += s.bytesDn
		for k, v := range s.kinds {
			all.kinds[k] += v
		}
	}
	lines = append(lines, line("TOTAL", all))
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}

func startDelay(i, n int, ramp time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	return ramp * time.Duration(i) / time.Duration(n)
}

type failureStreak struct {
	n     atomic.Int64
	limit int64
}

func (s *failureStreak) failed() error {
	if n := s.n.Add(1); n > s.limit {
		return fmt.Errorf("%w: %d operations failed in a row across all phones", errNoTunnelWorks, n)
	}
	return nil
}

func (s *failureStreak) succeeded() { s.n.Store(0) }

func nextBackoff(cur, interval, ceiling time.Duration) time.Duration {
	return max(interval, min(2*cur, ceiling))
}

func afterOp(ok bool, backoff, interval, ceiling time.Duration) time.Duration {
	if ok {
		return 0
	}
	return nextBackoff(backoff, interval, ceiling)
}

type worker struct {
	phone      string
	delay      time.Duration
	url        string
	client     *http.Client
	closeIdle  func()
	cfg        config
	rec        *recorder
	maxBackoff time.Duration
	streak     *failureStreak
}

func (w *worker) run(ctx context.Context) error {
	timer := time.NewTimer(w.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
	}
	recon := time.NewTicker(w.cfg.reconnect)
	defer recon.Stop()
	var backoff time.Duration
	timer.Reset(0)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-recon.C:
			w.closeIdle()
			continue
		case <-timer.C:
		}
		next := time.Now().Add(w.cfg.interval)
		ok, err := w.op(ctx)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if ok {
			w.streak.succeeded()
		} else if err := w.streak.failed(); err != nil {
			return err
		}
		if backoff = afterOp(ok, backoff, w.cfg.interval, w.maxBackoff); backoff > 0 {
			next = time.Now().Add(backoff)
		}
		timer.Reset(time.Until(next))
	}
}

func (w *worker) op(parent context.Context) (bool, error) {
	reqN, err := sizeAround(w.cfg.reqBytes)
	if err != nil {
		return false, err
	}
	respN, err := sizeAround(w.cfg.respBytes)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(parent, w.cfg.timeout)
	defer cancel()
	var newConn atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { newConn.Store(!i.Reused) }})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url+"?resp="+strconv.Itoa(respN), bytes.NewReader(pattern(reqN)))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := w.client.Do(req)
	if err != nil {
		if parent.Err() == nil {
			w.rec.failure(w.phone, classify(err), err)
		}
		return false, nil
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if cerr := resp.Body.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	lat := time.Since(start)
	if parent.Err() != nil {
		return false, nil
	}
	switch {
	case readErr != nil:
		w.rec.failure(w.phone, classify(readErr), readErr)
	case resp.StatusCode != http.StatusOK:
		w.rec.failure(w.phone, "status_"+strconv.Itoa(resp.StatusCode), fmt.Errorf("HTTP %d", resp.StatusCode))
	default:
		if verr := verify(body, respN); verr != nil {
			w.rec.failure(w.phone, "verify", verr)
		} else {
			w.rec.success(w.phone, lat, reqN, len(body), newConn.Load())
			return true, nil
		}
	}
	return false, nil
}

func transportFactory(cfg config) (func() *http.Transport, error) {
	var roots *x509.CertPool
	if cfg.caFile != "" {
		pem, err := os.ReadFile(cfg.caFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-file %s holds no PEM certificates", cfg.caFile)
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dial := dialer.DialContext
	if cfg.connect != "" {
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, cfg.connect)
		}
	}
	return func() *http.Transport {
		return &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext:         dial,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		}
	}, nil
}

type soakOptions struct {
	newTransport func() *http.Transport
	flushEvery   time.Duration
	maxBackoff   time.Duration
	maxFailures  int64
}

func soak(ctx context.Context, cfg config, names []string, rec *recorder, opts soakOptions) error {
	g, gctx := errgroup.WithContext(ctx)
	streak := &failureStreak{limit: opts.maxFailures}
	for i, name := range names {
		tr := opts.newTransport()
		w := &worker{
			phone: name, delay: startDelay(i, len(names), cfg.ramp), url: "https://" + name + "." + cfg.domain + "/op",
			client: &http.Client{Transport: tr}, closeIdle: tr.CloseIdleConnections, cfg: cfg, rec: rec,
			maxBackoff: opts.maxBackoff, streak: streak,
		}
		g.Go(func() error {
			defer tr.CloseIdleConnections()
			return w.run(gctx)
		})
	}
	g.Go(func() error {
		t := time.NewTicker(opts.flushEvery)
		defer t.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case now := <-t.C:
				if err := rec.flush(now); err != nil {
					return err
				}
			}
		}
	})
	werr := g.Wait()
	if err := rec.flush(time.Now()); err != nil {
		return errors.Join(werr, err)
	}
	return werr
}

func Run(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	newTransport, err := transportFactory(cfg)
	if err != nil {
		return err
	}
	nf, err := os.Open(cfg.namesFile)
	if err != nil {
		return fmt.Errorf("open names file: %w", err)
	}
	names, err := readNames(nf)
	if cerr := nf.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("close names file: %w", cerr)
	}
	if err != nil {
		return err
	}
	out, err := os.Create(cfg.out)
	if err != nil {
		return fmt.Errorf("create %s: %w", cfg.out, err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()
	logger.Info("soak started", "phones", len(names), "domain", cfg.domain, "interval", cfg.interval,
		"req_bytes", cfg.reqBytes, "resp_bytes", cfg.respBytes, "reconnect", cfg.reconnect, "ramp", cfg.ramp, "duration", cfg.duration, "out", cfg.out)
	rec, err := newRecorder(out, names, time.Now(), logger)
	if err != nil {
		return errors.Join(err, out.Close())
	}
	serr := soak(ctx, cfg, names, rec, soakOptions{newTransport: newTransport, flushEvery: time.Minute, maxBackoff: maxBackoff, maxFailures: maxFailures})
	if cerr := out.Close(); cerr != nil {
		serr = errors.Join(serr, fmt.Errorf("close %s: %w", cfg.out, cerr))
	}
	if err := rec.summary(stdout); err != nil {
		serr = errors.Join(serr, fmt.Errorf("write summary: %w", err))
	}
	return serr
}
