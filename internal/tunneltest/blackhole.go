package tunneltest

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

type BlackholeProxy struct {
	t      *testing.T
	ln     *net.TCPListener
	target *net.TCPAddr
	mu     sync.Mutex
	closed bool
	conns  []*proxiedConn
	count  atomic.Int64
	wg     sync.WaitGroup
}

type proxiedConn struct {
	client, upstream *net.TCPConn
	frozen           atomic.Bool
}

func StartBlackholeProxy(t *testing.T, target string) *BlackholeProxy {
	t.Helper()
	raddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &BlackholeProxy{t: t, ln: ln, target: raddr}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closed = true
		conns := slices.Clone(p.conns)
		p.mu.Unlock()
		CloseOrLog(t, ln)
		for _, c := range conns {
			CloseOrLog(t, c.client)
			CloseOrLog(t, c.upstream)
		}
		p.wg.Wait()
	})
	return p
}

func (p *BlackholeProxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.t.Logf("blackhole proxy: accept: %v", err)
			}
			return
		}
		up, err := net.DialTCP("tcp", nil, p.target)
		if err != nil {
			p.t.Logf("blackhole proxy: dial %s: %v", p.target, err)
			CloseOrLog(p.t, c)
			continue
		}
		pc := &proxiedConn{client: c, upstream: up}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			CloseOrLog(p.t, c)
			CloseOrLog(p.t, up)
			return
		}
		p.conns = append(p.conns, pc)
		p.count.Add(1)
		p.wg.Add(1)
		p.mu.Unlock()
		var pair sync.WaitGroup
		pair.Add(2)
		go p.pipe(pc, pc.client, pc.upstream, &pair)
		go p.pipe(pc, pc.upstream, pc.client, &pair)
		go p.reap(pc, &pair)
	}
}

func (p *BlackholeProxy) reap(pc *proxiedConn, pair *sync.WaitGroup) {
	defer p.wg.Done()
	pair.Wait()
	p.mu.Lock()
	p.conns = slices.DeleteFunc(p.conns, func(c *proxiedConn) bool { return c == pc })
	p.mu.Unlock()
	CloseOrLog(p.t, pc.client)
	CloseOrLog(p.t, pc.upstream)
}

func (p *BlackholeProxy) pipe(pc *proxiedConn, src, dst *net.TCPConn, pair *sync.WaitGroup) {
	defer pair.Done()
	buf := make([]byte, 16384)
	for {
		n, err := src.Read(buf)
		if n > 0 && !pc.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if !errors.Is(werr, net.ErrClosed) {
					p.t.Logf("blackhole proxy: write: %v", werr)
				}
				return
			}
		}
		if err != nil {
			if pc.frozen.Load() {
				return
			}
			if cerr := dst.CloseWrite(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
				p.t.Logf("blackhole proxy: half-close after %v: %v", err, cerr)
			}
			return
		}
	}
}

func (p *BlackholeProxy) Freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.frozen.Store(true)
	}
}

func (p *BlackholeProxy) Accepted() int64 { return p.count.Load() }

func (p *BlackholeProxy) Addr() string { return p.ln.Addr().String() }
