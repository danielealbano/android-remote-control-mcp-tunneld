package soak

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseConfig_Variants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "defaults with required flags", args: []string{"--names-file", "n.txt", "--domain", "t.example.test"}},
		{name: "missing names file", args: []string{"--domain", "t.example.test"}, wantErr: true},
		{name: "missing domain", args: []string{"--names-file", "n.txt"}, wantErr: true},
		{name: "zero interval", args: []string{"--names-file", "n.txt", "--domain", "d", "--interval", "0s"}, wantErr: true},
		{name: "negative request size", args: []string{"--names-file", "n.txt", "--domain", "d", "--req-bytes", "-1"}, wantErr: true},
		{name: "response above the phone limit", args: []string{"--names-file", "n.txt", "--domain", "d", "--resp-bytes", "40000"}, wantErr: true},
		{name: "unknown flag", args: []string{"--names-file", "n.txt", "--domain", "d", "--bogus"}, wantErr: true},
		{name: "connect without a port", args: []string{"--names-file", "n.txt", "--domain", "d", "--connect", "127.0.0.1"}, wantErr: true},
		{name: "connect host and port", args: []string{"--names-file", "n.txt", "--domain", "d", "--connect", "127.0.0.1:8443"}},
		{name: "negative ramp", args: []string{"--names-file", "n.txt", "--domain", "d", "--ramp", "-1s"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := parseConfig(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseConfig(%v) error = %v, wantErr %v", tc.args, err, tc.wantErr)
			}
			if err == nil && (c.interval != time.Second || c.reqBytes != 1024 || c.respBytes != 5120 || c.reconnect != 5*time.Minute || c.duration != 24*time.Hour) {
				t.Fatalf("defaults = %+v", c)
			}
		})
	}
}

func TestReadNames_Variants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "names with blank lines", input: "abc23\n\n  def45 \n", want: []string{"abc23", "def45"}},
		{name: "empty", input: "\n\n", wantErr: true},
		{name: "invalid characters", input: "abc\nbad.name\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := readNames(strings.NewReader(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("readNames error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("readNames = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSizeAround_RangeAndMean(t *testing.T) {
	t.Parallel()
	for _, avg := range []int{1024, 5120} {
		t.Run(strconv.Itoa(avg), func(t *testing.T) {
			t.Parallel()
			const samples = 20000
			sum := 0
			for range samples {
				n, err := sizeAround(avg)
				if err != nil {
					t.Fatal(err)
				}
				if n < minSize(avg) || n > maxSize(avg) {
					t.Fatalf("size %d outside [%d, %d]", n, minSize(avg), maxSize(avg))
				}
				sum += n
			}
			if mean := float64(sum) / samples; mean < 0.97*float64(avg) || mean > 1.03*float64(avg) {
				t.Fatalf("mean %.1f is not within 3%% of %d", mean, avg)
			}
		})
	}
}

func TestPattern_MatchesThePhoneFormula(t *testing.T) {
	t.Parallel()
	b := pattern(600)
	for _, i := range []int{0, 1, 250, 251, 252, 599} {
		if b[i] != byte(i%251) {
			t.Fatalf("pattern[%d] = %d, want %d", i, b[i], i%251)
		}
	}
}

func TestVerify_Variants(t *testing.T) {
	t.Parallel()
	corrupted := pattern(300)
	corrupted[260] ^= 0xff
	tests := []struct {
		name    string
		body    []byte
		n       int
		wantErr bool
	}{
		{name: "intact", body: pattern(300), n: 300},
		{name: "empty", body: nil, n: 0},
		{name: "short", body: pattern(299), n: 300, wantErr: true},
		{name: "long", body: pattern(301), n: 300, wantErr: true},
		{name: "corrupted byte", body: corrupted, n: 300, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := verify(tc.body, tc.n); (err != nil) != tc.wantErr {
				t.Fatalf("verify error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestPercentile_Variants(t *testing.T) {
	t.Parallel()
	ten := make([]time.Duration, 10)
	for i := range ten {
		ten[i] = time.Duration(i+1) * time.Millisecond
	}
	tests := []struct {
		name   string
		sorted []time.Duration
		p      float64
		want   time.Duration
	}{
		{name: "empty", sorted: nil, p: 50, want: 0},
		{name: "single", sorted: []time.Duration{7 * time.Millisecond}, p: 99, want: 7 * time.Millisecond},
		{name: "median of ten", sorted: ten, p: 50, want: 5 * time.Millisecond},
		{name: "p99 of ten", sorted: ten, p: 99, want: 10 * time.Millisecond},
		{name: "p95 of ten", sorted: ten, p: 95, want: 10 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := percentile(tc.sorted, tc.p); got != tc.want {
				t.Fatalf("percentile(p%.0f) = %s, want %s", tc.p, got, tc.want)
			}
		})
	}
}

func TestRecorder_FlushWritesOneRowPerPhoneAndLogsEachKindOnce(t *testing.T) {
	t.Parallel()
	var out, logs bytes.Buffer
	start := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	rec, err := newRecorder(&out, []string{"aaa", "bbb"}, start, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec.success("aaa", 10*time.Millisecond, 1000, 5000, true)
	rec.success("aaa", 30*time.Millisecond, 1000, 5000, false)
	rec.failure("aaa", "timeout", errors.New("deadline"))
	rec.failure("aaa", "timeout", errors.New("deadline again"))
	rec.failure("aaa", "status_502", errors.New("HTTP 502"))
	if err := rec.flush(start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d CSV rows, want header + 2", len(rows))
	}
	want := []string{"2026-10-14T12:00:00Z", "aaa", "2", "3", "status_502=1;timeout=2", "10.0", "30.0", "30.0", "30.0", "1", "2000", "10000"}
	if strings.Join(rows[1], ",") != strings.Join(want, ",") {
		t.Fatalf("row = %v, want %v", rows[1], want)
	}
	if rows[2][1] != "bbb" || rows[2][2] != "0" || rows[2][3] != "0" {
		t.Fatalf("idle phone row = %v", rows[2])
	}
	if n := strings.Count(logs.String(), "kind=timeout"); n != 1 {
		t.Fatalf("timeout logged %d times in one minute, want 1", n)
	}
	rec.failure("aaa", "timeout", errors.New("next minute"))
	if n := strings.Count(logs.String(), "kind=timeout"); n != 2 {
		t.Fatalf("timeout logged %d times after the minute rolled, want 2", n)
	}
	var summary bytes.Buffer
	if err := rec.summary(&summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "TOTAL") || !strings.Contains(summary.String(), "ok=2 errors=4") {
		t.Fatalf("summary = %q", summary.String())
	}
}

func fakePhone(t *testing.T, short bool) (*httptest.Server, func() *http.Transport) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/op" {
			http.NotFound(w, r)
			return
		}
		n, err := strconv.Atoi(r.URL.Query().Get("resp"))
		if err != nil || n < 0 || n > maxResponse {
			http.Error(w, "bad resp", http.StatusBadRequest)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if short {
			n--
		}
		if _, err := w.Write(pattern(n)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return srv, func() *http.Transport {
		d := &net.Dialer{}
		return &http.Transport{
			MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		}
	}
}

func testConfig() config {
	return config{domain: "t.example.test", interval: 5 * time.Millisecond, reqBytes: 1024, respBytes: 5120,
		reconnect: 40 * time.Millisecond, duration: time.Minute, timeout: 5 * time.Second}
}

func runSoakUntil(t *testing.T, names []string, transport func() *http.Transport, done func(*recorder) bool) (*recorder, []byte, string) {
	t.Helper()
	var out, logs bytes.Buffer
	rec, err := newRecorder(&out, names, time.Now(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- soak(ctx, testConfig(), names, rec, soakOptions{newTransport: transport, flushEvery: 20 * time.Millisecond})
	}()
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Minute)
	}
	for {
		rec.mu.Lock()
		finished := done(rec)
		rec.mu.Unlock()
		if finished {
			break
		}
		if time.Now().After(deadline.Add(-5 * time.Second)) {
			cancel()
			<-result
			t.Fatalf("condition not reached before the test deadline; logs: %s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return rec, out.Bytes(), logs.String()
}

func TestSoak_AgainstFakePhonesReusesAndReconnects(t *testing.T) {
	t.Parallel()
	_, transport := fakePhone(t, false)
	names := []string{"aaa", "bbb"}
	rec, out, logs := runSoakUntil(t, names, transport, func(r *recorder) bool {
		for _, p := range names {
			if s := r.total[p]; s.ok < 10 || s.newConns < 2 {
				return false
			}
		}
		return true
	})
	for _, p := range names {
		s := rec.total[p]
		if s.errors != 0 {
			t.Fatalf("%s: errors=%d kinds=%v logs=%s", p, s.errors, s.kinds, logs)
		}
		if s.newConns >= s.ok {
			t.Fatalf("%s: new_conns=%d for ok=%d; the connection is not reused", p, s.newConns, s.ok)
		}
		if s.bytesDn < int64(s.ok*minSize(5120)) || s.bytesUp < int64(s.ok*minSize(1024)) {
			t.Fatalf("%s: bytes up=%d down=%d for ok=%d", p, s.bytesUp, s.bytesDn, s.ok)
		}
	}
	rows, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1+len(names) || (len(rows)-1)%len(names) != 0 {
		t.Fatalf("got %d CSV rows, want the header plus whole flushes of %d phones", len(rows), len(names))
	}
}

func TestSoak_CountsCorruptResponsesAsVerifyErrors(t *testing.T) {
	t.Parallel()
	_, transport := fakePhone(t, true)
	rec, _, logs := runSoakUntil(t, []string{"aaa"}, transport, func(r *recorder) bool { return r.total["aaa"].errors >= 3 })
	s := rec.total["aaa"]
	if s.ok != 0 || s.kinds["verify"] != s.errors {
		t.Fatalf("ok=%d errors=%d kinds=%v", s.ok, s.errors, s.kinds)
	}
	if !strings.Contains(logs, "kind=verify") {
		t.Fatalf("verify failure not logged: %s", logs)
	}
}

func TestRun_TrustsTheCAFileAndDialsTheConnectAddress(t *testing.T) {
	t.Parallel()
	srv, _ := fakePhone(t, false)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	namesFile := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(namesFile, []byte("example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "soak.csv")
	var stdout, logs bytes.Buffer
	err := Run(context.Background(), []string{
		"--names-file", namesFile, "--domain", "com", "--ca-file", caFile, "--connect", srv.Listener.Addr().String(),
		"--interval", "10ms", "--reconnect", "50ms", "--duration", "400ms", "--out", out,
	}, &stdout, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "TOTAL") || !strings.Contains(stdout.String(), " errors=0 ") || strings.Contains(stdout.String(), "TOTAL          ok=0 ") {
		t.Fatalf("summary = %q, logs = %s", stdout.String(), logs.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || rows[1][1] != "example" {
		t.Fatalf("CSV rows = %v", rows)
	}
}

func TestRun_RejectsACAFileWithoutCertificates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{"--names-file", filepath.Join(dir, "names.txt"), "--domain", "com", "--ca-file", caFile},
		io.Discard, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("Run error = %v, want a no-certificates error", err)
	}
}

func TestStartDelay_Variants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		i, n int
		ramp time.Duration
		want time.Duration
	}{
		{name: "no ramp", i: 7, n: 50, ramp: 0, want: 0},
		{name: "first phone starts at once", i: 0, n: 50, ramp: 30 * time.Second, want: 0},
		{name: "evenly spread", i: 25, n: 50, ramp: 30 * time.Second, want: 15 * time.Second},
		{name: "last phone before the ramp ends", i: 49, n: 50, ramp: 30 * time.Second, want: 29400 * time.Millisecond},
		{name: "no phones", i: 0, n: 0, ramp: 30 * time.Second, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := startDelay(tc.i, tc.n, tc.ramp); got != tc.want {
				t.Fatalf("startDelay(%d, %d, %s) = %s, want %s", tc.i, tc.n, tc.ramp, got, tc.want)
			}
		})
	}
}
