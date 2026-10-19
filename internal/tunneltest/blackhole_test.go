package tunneltest

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type testTarget struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

func startTarget(t *testing.T, handle func(net.Conn)) *testTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tt := &testTarget{ln: ln}
	tt.wg.Add(1)
	go func() {
		defer tt.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tt.mu.Lock()
			tt.conns = append(tt.conns, c)
			tt.wg.Add(1)
			tt.mu.Unlock()
			go func() {
				defer tt.wg.Done()
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() {
		CloseOrLog(t, ln)
		tt.mu.Lock()
		conns := tt.conns
		tt.mu.Unlock()
		for _, c := range conns {
			CloseOrLog(t, c)
		}
		tt.wg.Wait()
	})
	return tt
}

func echo(c net.Conn) {
	if _, err := io.Copy(c, c); err != nil && !errors.Is(err, net.ErrClosed) {
		Logger().Debug("test echo target: copy ended", "err", err)
	}
}

func dialProxy(t *testing.T, p *BlackholeProxy) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CloseOrLog(t, c) })
	return c
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func expectSilence(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(make([]byte, 16))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("frozen connection: read n=%d err=%v, want a read timeout (no bytes, not closed)", n, err)
	}
}

func expectEOF(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 16)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want EOF", err)
	}
}

func TestBlackholeProxy_ForwardsThenFreezes(t *testing.T) {
	t.Parallel()
	target := startTarget(t, echo)
	p := StartBlackholeProxy(t, target.ln.Addr().String())

	first := dialProxy(t, p)
	roundTrip(t, first, "before")
	p.Freeze()
	if _, err := first.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	expectSilence(t, first)

	second := dialProxy(t, p)
	roundTrip(t, second, "fresh")
	if got := p.Accepted(); got != 2 {
		t.Fatalf("Accepted() = %d, want 2", got)
	}
}

func TestBlackholeProxy_PropagatesClose(t *testing.T) {
	t.Parallel()
	t.Run("target closes", func(t *testing.T) {
		target := startTarget(t, func(c net.Conn) { CloseLogged(c) })
		p := StartBlackholeProxy(t, target.ln.Addr().String())
		expectEOF(t, dialProxy(t, p))
	})
	t.Run("client half-closes", func(t *testing.T) {
		gotEOF := make(chan error, 1)
		target := startTarget(t, func(c net.Conn) {
			_, err := io.Copy(io.Discard, c)
			gotEOF <- err
		})
		p := StartBlackholeProxy(t, target.ln.Addr().String())
		c := dialProxy(t, p)
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-gotEOF:
			if err != nil {
				t.Fatalf("target read ended with %v, want a clean EOF", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("target never saw the client's half-close")
		}
	})
	t.Run("frozen propagates nothing", func(t *testing.T) {
		release := make(chan struct{})
		target := startTarget(t, func(c net.Conn) {
			<-release
			CloseLogged(c)
		})
		p := StartBlackholeProxy(t, target.ln.Addr().String())
		c := dialProxy(t, p)
		waitFor(t, func() bool { return p.Accepted() == 1 })
		p.Freeze()
		close(release)
		expectSilence(t, c)
	})
	t.Run("finished pairs are reaped", func(t *testing.T) {
		target := startTarget(t, func(c net.Conn) { CloseLogged(c) })
		p := StartBlackholeProxy(t, target.ln.Addr().String())
		c := dialProxy(t, p)
		expectEOF(t, c)
		CloseOrLog(t, c)
		waitFor(t, func() bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return len(p.conns) == 0
		})
	})
}

func TestBlackholeProxy_CleanupNeverHangs(t *testing.T) {
	t.Parallel()
	target := startTarget(t, echo)
	var dials sync.WaitGroup
	t.Run("proxy", func(t *testing.T) {
		p := StartBlackholeProxy(t, target.ln.Addr().String())
		for range 10 {
			dials.Go(func() {
				c, err := net.DialTimeout("tcp", p.Addr(), time.Second)
				if err != nil {
					return
				}
				CloseLogged(c)
			})
		}
		roundTrip(t, dialProxy(t, p), "x")
	})
	dials.Wait()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
