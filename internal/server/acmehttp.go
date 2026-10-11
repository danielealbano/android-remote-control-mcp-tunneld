package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	acmeHTTPIdleTimeout    = 30 * time.Second
	acmeHTTPMaxHeaderBytes = 8 << 10
)

type connRateLimiter interface {
	Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (bool, time.Duration, error)
}

func connRateAllow(lim connRateLimiter, rate int, logger *slog.Logger) func(context.Context, netip.Addr) bool {
	return func(ctx context.Context, ip netip.Addr) bool {
		ok, _, err := lim.Allow(ctx, "conn-rate", ip, rate, time.Second)
		if err != nil {
			logger.Debug("acme-http conn-rate check failed (allowing)", "ip", ip, "err", err)
			return true
		}
		return ok
	}
}

type guardedListener struct {
	ln      net.Listener
	ban     func(netip.Addr) bool
	allow   func(context.Context, netip.Addr) bool
	admit   func() bool
	release func()
	reject  func(reason, tunnelName, clientIP string)
	logger  *slog.Logger
	conns   chan net.Conn
	closed  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func newGuardedListener(ctx context.Context, ln net.Listener, ban func(netip.Addr) bool,
	allow func(context.Context, netip.Addr) bool, admit func() bool, release func(),
	reject func(reason, tunnelName, clientIP string), logger *slog.Logger) *guardedListener {
	l := &guardedListener{
		ln: ln, ban: ban, allow: allow, admit: admit, release: release, reject: reject, logger: logger,
		conns: make(chan net.Conn), closed: make(chan struct{}),
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.acceptLoop(ctx)
	}()
	return l
}

func (l *guardedListener) acceptLoop(ctx context.Context) {
	var delay time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			l.logger.Warn("acme-http accept failed (backing off)", "backoff", delay, "err", err)
			select {
			case <-time.After(delay):
			case <-l.closed:
				return
			}
			continue
		}
		delay = 0
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.check(ctx, c)
		}()
	}
}

func (l *guardedListener) check(ctx context.Context, c net.Conn) {
	host, _, serr := net.SplitHostPort(c.RemoteAddr().String())
	if serr != nil {
		host = c.RemoteAddr().String()
	}
	ip, perr := netip.ParseAddr(host)
	if perr == nil && l.ban(ip) {
		l.reject("ban", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	if perr == nil && !l.allow(ctx, ip) {
		l.reject("conn-rate", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	if !l.admit() {
		l.reject("max-clients", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	sc := &slotConn{Conn: c, release: l.release}
	select {
	case l.conns <- sc:
	case <-l.closed:
		closeLogged(l.logger, "acme-http pending conn", sc)
	}
}

func (l *guardedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *guardedListener) Close() error {
	err := net.ErrClosed
	l.once.Do(func() {
		close(l.closed)
		err = l.ln.Close()
	})
	return err
}

func (l *guardedListener) Addr() net.Addr { return l.ln.Addr() }

func (l *guardedListener) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { l.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
