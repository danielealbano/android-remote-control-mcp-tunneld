package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
)

// peekConn is a net.Conn that replays a buffered prefix (the peeked ClientHello) before the underlying
// stream, so a downstream TLS terminator re-reads the full handshake.
type peekConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// chanListener is a net.Listener fed conns from a channel (used to hand reserved-SNI conns to the
// enroll/control HTTP servers behind a tls.NewListener).
type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{ch: make(chan net.Conn, 64), addr: addr, closed: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *chanListener) Addr() net.Addr { return l.addr }

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

// peekClientHello reads the first TLS record (the ClientHello) from conn within the handshake deadline
// and returns it plus a peekConn that replays it.
func peekClientHello(conn net.Conn, deadline time.Duration) (ClientHelloInfo, *peekConn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return ClientHelloInfo{}, nil, err
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16*1024 {
		return ClientHelloInfo{}, nil, errBadClientHello
	}
	record := make([]byte, 5+recLen)
	copy(record, hdr[:])
	if _, err := io.ReadFull(conn, record[5:]); err != nil {
		return ClientHelloInfo{}, nil, err
	}
	info, err := parseClientHello(record)
	if err != nil {
		return ClientHelloInfo{}, nil, err
	}
	return info, &peekConn{Conn: conn, prefix: record}, nil
}

// acceptLoop accepts raw TCP connections and hands each to handleConn (which applies the accept-time
// checks in the documented order). It runs until ctx is done or the listener closes.
func (e *Edge) acceptLoop(ctx context.Context, ln net.Listener) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Exponential backoff (5ms→1s): persistent errors (e.g. EMFILE) must not hot-spin.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		delay = 0
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.handleConn(ctx, conn)
		}()
	}
}

// admit enforces the global --max-clients ceiling.
func (e *Edge) admit() bool {
	n := e.clients.Add(1)
	if int(n) > e.cfg.MaxClients {
		e.clients.Add(-1)
		return false
	}
	return true
}

func (e *Edge) release() { e.clients.Add(-1) }

// heldConn keeps the --max-clients slot held for the LIFETIME of a reserved-host (enroll/control)
// connection handed to a local TLS terminator: the slot releases when the connection closes, so
// long-lived phone control connections still count toward the global ceiling.
type heldConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *heldConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// NetConn exposes the wrapped conn so phoneconn.ConnContext can unwrap through this holder.
func (c *heldConn) NetConn() net.Conn { return c.Conn }

func (e *Edge) handleConn(ctx context.Context, conn net.Conn) {
	ip := peerAddr(conn)
	addr, addrErr := netip.ParseAddr(ip)

	// Accept-time checks in the documented order: ban FIRST, then the per-IP rate, then the global
	// --max-clients ceiling (a banned IP must be recorded as banned even on a saturated node).
	if addrErr == nil && e.ban != nil && e.ban(addr) {
		e.rec.Reject("ban", "", ip)
		_ = conn.Close()
		return
	}
	if addrErr == nil && !e.connRate(ctx, addr) {
		e.rec.Reject("conn-rate", "", ip)
		_ = conn.Close()
		return
	}
	if !e.admit() {
		e.rec.Reject("max-clients", "", ip)
		_ = conn.Close()
		return
	}
	released := false
	defer func() {
		if !released {
			e.release()
		}
	}()

	info, pc, err := peekClientHello(conn, e.cfg.HandshakeTimeout)
	if err != nil {
		e.rec.Reject("handshake-timeout", "", ip)
		_ = conn.Close()
		return
	}

	// Reserved SNIs → local TLS terminators. The max-clients slot moves to the pushed conn (heldConn
	// releases it on Close) so reserved-host connections stay counted for their whole lifetime. SNI is
	// matched case-insensitively (DNS is case-insensitive); the raw info.SNI stays in logs/JA4.
	switch strings.ToLower(info.SNI) {
	case e.cfg.EnrollHost:
		released = true
		e.enrollLn.push(&heldConn{Conn: pc, release: e.release})
		return
	case e.cfg.ControlHost:
		released = true
		e.controlLn.push(&heldConn{Conn: withMeta(pc, info, conn), release: e.release})
		return
	}
	// Tunnel SNI (the slot releases when handleTunnel returns — the splice runs within it).
	e.handleTunnel(ctx, pc, info)
}

func peerAddr(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// withMeta wraps the control-host conn so the phoneconn handler can read the peeked ClientHello
// metadata (JA4/ALPN/version + peer address) for its phone connection-log events. server.Run wires
// phoneconn.ConnContext on the control listener, which unwraps the tls.Conn to this carrier.
func withMeta(pc *peekConn, info ClientHelloInfo, raw net.Conn) net.Conn {
	srcIP, srcPort := splitAddr(raw.RemoteAddr())
	return &metaConn{
		Conn: pc,
		meta: phoneconn.ConnMeta{
			SNI: info.SNI, ALPN: info.ALPN, TLSVersion: info.TLSVersion, JA4: info.JA4,
			SrcIP: srcIP, SrcPort: srcPort,
		},
	}
}

// metaConn carries the peeked ConnMeta to the phone control handler (via phoneconn.ConnMetaCarrier).
type metaConn struct {
	net.Conn
	meta phoneconn.ConnMeta
}

func (c *metaConn) ConnMeta() phoneconn.ConnMeta { return c.meta }

// NetConn exposes the wrapped connection so a tls.Conn layered on top can be unwrapped to this carrier.
func (c *metaConn) NetConn() net.Conn { return c.Conn }
