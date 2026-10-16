package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

func newSilenceClient(t *testing.T, dialAddr string, s *h2TestServer, silence time.Duration) *Client {
	t.Helper()
	c, err := New(dialAddr, testEnrollHost, testControlHost, testTunnelDomain, s.pool, newCAIdentity(t, newTestCA(t)),
		func(io.ReadWriteCloser) {}, WithControlSilenceTimeout(silence))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func runResult(ctx context.Context, c *Client) <-chan error {
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	return done
}

func waitRun(t *testing.T, done <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("Run did not return within %s", within)
		return nil
	}
}

func bindHandler(bound chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case bound <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
}

func TestRun_SilenceBeforeHeaders(t *testing.T) {
	s := startH2TestServer(t, []string{"h2"}, 0, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	c := newSilenceClient(t, s.addr, s, 200*time.Millisecond)
	if err := waitRun(t, runResult(context.Background(), c), 5*time.Second); !errors.Is(err, errControlSilence) {
		t.Fatalf("Run = %v, want errControlSilence", err)
	}
}

func TestRun_SilenceAfterBind(t *testing.T) {
	bound := make(chan struct{}, 1)
	s := startH2TestServer(t, []string{"h2"}, 0, bindHandler(bound))
	c := newSilenceClient(t, s.addr, s, 200*time.Millisecond)
	done := runResult(context.Background(), c)
	select {
	case <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("the control stream never bound")
	}
	if err := waitRun(t, done, 5*time.Second); !errors.Is(err, errControlSilence) {
		t.Fatalf("Run = %v, want errControlSilence", err)
	}
}

func TestRun_FramesResetSilence(t *testing.T) {
	ping, err := wire.EncodeControl(wire.CtrlPing, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := startH2TestServer(t, []string{"h2"}, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				if _, err := w.Write(ping); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}))
	c := newSilenceClient(t, s.addr, s, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runResult(ctx, c)
	select {
	case err := <-done:
		t.Fatalf("Run returned %v while PINGs kept arriving", err)
	case <-time.After(3 * time.Second):
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Fatalf("Run after ctx cancel = %v, want nil", err)
	}
}

func TestRun_DeadConnectionIsReplaced(t *testing.T) {
	bound := make(chan struct{}, 1)
	s := startH2TestServer(t, []string{"h2"}, 0, bindHandler(bound))
	p := tunneltest.StartBlackholeProxy(t, s.addr)
	c := newSilenceClient(t, p.Addr(), s, 300*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := runResult(ctx, c)
	select {
	case <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("the first control stream never bound")
	}
	accepted := p.Accepted()
	p.Freeze()
	if err := waitRun(t, first, 5*time.Second); !errors.Is(err, errControlSilence) {
		t.Fatalf("Run over the frozen connection = %v, want errControlSilence", err)
	}

	second := runResult(ctx, c)
	select {
	case <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("the next Run never bound again")
	}
	if got := p.Accepted(); got != accepted+1 {
		t.Fatalf("the next Run must dial one new connection: accepted %d → %d", accepted, got)
	}
	cancel()
	if err := waitRun(t, second, 5*time.Second); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after ctx cancel = %v, want nil or the cancellation", err)
	}
}

func TestWithControlSilenceTimeout_NonPositive(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := New("", "", "", "", nil, nil, nil, WithControlSilenceTimeout(d)); err == nil {
			t.Fatalf("WithControlSilenceTimeout(%s) must be rejected", d)
		}
	}
}

func TestRenew_NudgeSingleFlight(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	holding := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	opts := &enrollServerOpts{issueFail: func() *errorResponse {
		if calls.Add(1) == 1 {
			close(holding)
			<-release
		}
		return nil
	}}
	dialAddr, _ := startEnrollServer(t, ca, opts)
	var logs syncBuf
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := New(dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool, newCAIdentity(t, ca),
		func(io.ReadWriteCloser) {}, WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		c.renew(ctx, []byte(`{"nonce":"a1"}`))
	}()
	select {
	case <-holding:
	case <-time.After(5 * time.Second):
		t.Fatal("the first renewal never reached the issue endpoint")
	}
	c.renew(ctx, []byte(`{"nonce":"a2"}`))
	if got := opts.nonces(); len(got) != 1 {
		t.Fatalf("a nudge during a renewal must be ignored; issue requests %v", got)
	}
	if !strings.Contains(logs.String(), `msg="renewal already in progress; RENEW_NUDGE ignored"`) {
		t.Fatalf("the ignored nudge must be logged at Debug; log = %q", logs.String())
	}
	close(release)
	<-firstDone
	c.renew(ctx, []byte(`{"nonce":"a3"}`))
	if got := opts.nonces(); len(got) != 2 || got[1] != "a3" {
		t.Fatalf("a nudge after the renewal finished must issue again; issue requests %v", got)
	}
}
