package caplog

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

func newBufLogger() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return newLogger(log, time.Minute, time.Now), &buf
}

func TestCaplogLogsFirstHitImmediately(t *testing.T) {
	l, buf := newBufLogger()
	l.Hit("tunnelA", "rate_rps", "1.1.1.1")
	if n := strings.Count(buf.String(), `msg="refused a request: rate_rps"`); n != 1 {
		t.Errorf("first hit immediate logs = %d, want 1", n)
	}
}

func TestCaplogDedupsWithinWindow(t *testing.T) {
	l, buf := newBufLogger()
	for i := 0; i < 1000; i++ {
		l.Hit("tunnelA", "rate_rps", "1.1.1.1")
	}
	l.Flush()
	if n := strings.Count(buf.String(), `msg="refused a request: rate_rps"`); n != 1 {
		t.Errorf("immediate logs = %d, want exactly 1", n)
	}
	if n := strings.Count(buf.String(), `msg="refused requests repeatedly within one minute: rate_rps"`); n != 1 {
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
	if n := strings.Count(out, `msg="refused a request: r"`); n != 2 {
		t.Errorf("immediate logs = %d, want 2 (first hit of each window)", n)
	}
	if n := strings.Count(out, `msg="refused requests repeatedly within one minute: r"`); n < 1 {
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

func TestCaplog_ReadableSentencesAndLevels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, tunnel, reason string
		wantFirst, wantMore  string
		wantLevel            slog.Level
	}{
		{name: "internet noise is Info", reason: "handshake-timeout", wantLevel: slog.LevelInfo,
			wantFirst: "refused a connection: the client did not send a valid TLS greeting in time",
			wantMore:  "refused connections repeatedly within one minute: the clients did not send a valid TLS greeting in time"},
		{name: "a banned address", reason: "ban", wantLevel: slog.LevelInfo,
			wantFirst: "refused a connection from a banned address",
			wantMore:  "refused connections from banned addresses repeatedly within one minute"},
		{name: "a banned tunnel name", tunnel: "abcdef234567", reason: "ban", wantLevel: slog.LevelInfo,
			wantFirst: "refused a phone connection: the tunnel name is banned",
			wantMore:  "refused phone connections repeatedly within one minute: the tunnel name is banned"},
		{name: "a refused enrollment's certificate request", reason: "csr-mismatch", wantLevel: slog.LevelWarn,
			wantFirst: "refused an enrollment: its certificate signing request is badly signed or does not use the attested key",
			wantMore:  "refused enrollments repeatedly within one minute: their certificate signing requests are badly signed or do not use the attested key"},
		{name: "a refused certificate request", tunnel: "abcdef234567", reason: "csr-mismatch", wantLevel: slog.LevelWarn,
			wantFirst: "refused a certificate request: it is badly signed, uses an unsupported key or not the attested key, or does not ask for exactly the tunnel's name",
			wantMore:  "refused certificate requests repeatedly within one minute: they are badly signed, use an unsupported key or not the attested key, or do not ask for exactly the tunnel's name"},
		{name: "a limit a real user hits is Warn", tunnel: "abcdef234567", reason: "stream-cap", wantLevel: slog.LevelWarn,
			wantFirst: "refused a connection: the tunnel already has its maximum number of open connections",
			wantMore:  "refused connections repeatedly within one minute: the tunnel already has its maximum number of open connections"},
		{name: "an unknown reason is Warn", reason: "something-new", wantLevel: slog.LevelWarn,
			wantFirst: "refused a request: something-new",
			wantMore:  "refused requests repeatedly within one minute: something-new"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			l := newLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), time.Minute, time.Now)
			l.Hit(tc.tunnel, tc.reason, "198.51.100.1")
			l.Hit(tc.tunnel, tc.reason, "198.51.100.2")
			l.Flush()
			out := buf.String()
			level := "level=" + tc.wantLevel.String()
			for _, msg := range []string{tc.wantFirst, tc.wantMore} {
				if !strings.Contains(out, level+` msg="`+msg+`"`) {
					t.Errorf("want %s %q; log = %q", level, msg, out)
				}
			}
		})
	}
}

func TestCaplog_EveryRejectionReasonHasSentencesAndItsLevel(t *testing.T) {
	t.Parallel()
	noise := map[string]bool{"handshake-timeout": true, "ban": true, "ban-tunnel": true, "conn-rate": true, "acme-http-miss": true}
	reasons := append(append([]string(nil), observ.RejectReasons...), "quota-day", "quota-week", "ban-tunnel", "csr-mismatch-enroll")
	for _, r := range reasons {
		if r == "no-route" {
			continue
		}
		p, ok := phrasings[r]
		if !ok {
			t.Errorf("rejection reason %q has no readable sentence", r)
			continue
		}
		want := slog.LevelWarn
		if noise[r] {
			want = slog.LevelInfo
		}
		if p.level != want {
			t.Errorf("rejection reason %q logs at %s, want %s", r, p.level, want)
		}
		if p.first == "" || p.repeated == "" || p.first == p.repeated {
			t.Errorf("rejection reason %q needs a first and a different repeated sentence, got %q / %q", r, p.first, p.repeated)
		}
	}
}
