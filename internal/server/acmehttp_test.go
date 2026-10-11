package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type guardProbe struct {
	mu       sync.Mutex
	rejects  []string
	allows   atomic.Int32
	admits   atomic.Int32
	releases atomic.Int32
}

func (p *guardProbe) reject(reason, _, _ string) {
	p.mu.Lock()
	p.rejects = append(p.rejects, reason)
	p.mu.Unlock()
}

func (p *guardProbe) rejected() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.rejects...)
}

func newProbedGuard(t *testing.T, ban func(netip.Addr) bool, allow func(context.Context, netip.Addr) bool, admit func() bool) (*guardedListener, *guardProbe) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &guardProbe{}
	g := newGuardedListener(context.Background(), ln, ban,
		func(ctx context.Context, ip netip.Addr) bool { p.allows.Add(1); return allow(ctx, ip) },
		func() bool { p.admits.Add(1); return admit() },
		func() { p.releases.Add(1) }, p.reject)
	t.Cleanup(func() {
		_ = g.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Wait(ctx)
	})
	return g, p
}

func dialGuard(t *testing.T, g *guardedListener) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", g.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func expectClosedByPeer(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection must be closed by the guard, read err = %v", err)
	}
}

func TestGuardListener_Order(t *testing.T) {
	never := func(netip.Addr) bool { return false }
	always := func(netip.Addr) bool { return true }
	allowYes := func(context.Context, netip.Addr) bool { return true }
	allowNo := func(context.Context, netip.Addr) bool { return false }
	tests := []struct {
		name       string
		ban        func(netip.Addr) bool
		allow      func(context.Context, netip.Addr) bool
		admit      bool
		wantReason string
		wantAllows int32
		wantAdmits int32
	}{
		{name: "banned", ban: always, allow: allowYes, admit: true, wantReason: "ban", wantAllows: 0, wantAdmits: 0},
		{name: "over rate", ban: never, allow: allowNo, admit: true, wantReason: "conn-rate", wantAllows: 1, wantAdmits: 0},
		{name: "max clients", ban: never, allow: allowYes, admit: false, wantReason: "max-clients", wantAllows: 1, wantAdmits: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, p := newProbedGuard(t, tc.ban, tc.allow, func() bool { return tc.admit })
			c := dialGuard(t, g)
			expectClosedByPeer(t, c)
			if got := p.rejected(); len(got) != 1 || got[0] != tc.wantReason {
				t.Fatalf("rejects = %v, want [%s]", got, tc.wantReason)
			}
			if p.allows.Load() != tc.wantAllows || p.admits.Load() != tc.wantAdmits {
				t.Fatalf("allow calls=%d admit calls=%d, want %d/%d", p.allows.Load(), p.admits.Load(), tc.wantAllows, tc.wantAdmits)
			}
		})
	}
}

func TestGuardListener_SlowRateCheckDoesNotBlockAccept(t *testing.T) {
	unblock := make(chan struct{})
	var calls atomic.Int32
	allow := func(context.Context, netip.Addr) bool {
		if calls.Add(1) == 1 {
			<-unblock
		}
		return true
	}
	g, _ := newProbedGuard(t, func(netip.Addr) bool { return false }, allow, func() bool { return true })
	defer close(unblock)
	_ = dialGuard(t, g)
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	_ = dialGuard(t, g)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := g.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("a slow rate check on one connection blocked accepting the next")
	}
}

type fakeConnRateLimiter struct {
	ok     bool
	err    error
	scope  string
	limit  int
	window time.Duration
}

func (f *fakeConnRateLimiter) Allow(_ context.Context, scope string, _ netip.Addr, limit int, window time.Duration) (bool, time.Duration, error) {
	f.scope, f.limit, f.window = scope, limit, window
	return f.ok, 0, f.err
}

func TestConnRateAllow(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
		err  error
		want bool
	}{
		{name: "allowed", ok: true, want: true},
		{name: "denied", ok: false, want: false},
		{name: "limiter error fails open", err: errors.New("valkey down"), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeConnRateLimiter{ok: tc.ok, err: tc.err}
			got := connRateAllow(f, 42)(context.Background(), netip.MustParseAddr("192.0.2.1"))
			if got != tc.want {
				t.Fatalf("allow = %v, want %v", got, tc.want)
			}
			if f.scope != "conn-rate" || f.limit != 42 || f.window != time.Second {
				t.Fatalf("Allow(scope=%q limit=%d window=%s), want conn-rate/42/1s", f.scope, f.limit, f.window)
			}
		})
	}
}

type failingListener struct {
	mu     sync.Mutex
	times  []time.Time
	closed chan struct{}
	once   sync.Once
}

func (l *failingListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	l.mu.Lock()
	l.times = append(l.times, time.Now())
	l.mu.Unlock()
	return nil, errors.New("accept: too many open files")
}

func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *failingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80} }

func (l *failingListener) attempts() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.times...)
}

func TestGuardListener_AcceptErrorBackoff(t *testing.T) {
	fl := &failingListener{closed: make(chan struct{})}
	g := newGuardedListener(context.Background(), fl, func(netip.Addr) bool { return false },
		func(context.Context, netip.Addr) bool { return true }, func() bool { return true }, func() {},
		func(string, string, string) {})
	waitFor(t, 5*time.Second, func() bool { return len(fl.attempts()) >= 4 })
	times := fl.attempts()
	for i := 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap < 5*time.Millisecond {
			t.Fatalf("accept retry %d came after %s, want at least 5ms (no hot spin)", i, gap)
		}
	}
	_ = g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	g.Wait(ctx)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close during the backoff must end the accept loop, Wait took %s", elapsed)
	}
}

func TestGuardListener_SlotReleasedOnClose(t *testing.T) {
	g, p := newProbedGuard(t, func(netip.Addr) bool { return false },
		func(context.Context, netip.Addr) bool { return true }, func() bool { return true })
	_ = dialGuard(t, g)
	c, err := g.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = c.Close()
	if n := p.releases.Load(); n != 1 {
		t.Fatalf("slot released %d times, want exactly 1", n)
	}
}

func TestGuardListener_Close(t *testing.T) {
	g, p := newProbedGuard(t, func(netip.Addr) bool { return false },
		func(context.Context, netip.Addr) bool { return true }, func() bool { return true })
	c := dialGuard(t, g)
	waitFor(t, 5*time.Second, func() bool { return p.admits.Load() == 1 })
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
	expectClosedByPeer(t, c)
	waitFor(t, 5*time.Second, func() bool { return p.releases.Load() == 1 })
}

func TestGuardListener_WaitJoinsGoroutines(t *testing.T) {
	unblock := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	allow := func(context.Context, netip.Addr) bool {
		once.Do(func() { close(entered) })
		<-unblock
		return true
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := newGuardedListener(context.Background(), ln, func(netip.Addr) bool { return false }, allow,
		func() bool { return true }, func() {}, func(string, string, string) {})
	c := dialGuard(t, g)
	defer func() { _ = c.Close() }()
	<-entered
	_ = g.Close()

	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelShort()
	start := time.Now()
	g.Wait(short)
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("Wait returned after %s while a check was still running", elapsed)
	}

	close(unblock)
	long, cancelLong := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLong()
	start = time.Now()
	g.Wait(long)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Wait did not return once the check finished (%s)", elapsed)
	}
}
