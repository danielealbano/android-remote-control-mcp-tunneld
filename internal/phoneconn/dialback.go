package phoneconn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

var ErrDuplicateToken = errors.New("phoneconn: duplicate dial-back token")

type dialWaiter struct {
	tunnel string
	conn   chan net.Conn
}

type DialBacks struct {
	logger  *slog.Logger
	mu      sync.Mutex
	waiting map[string]*dialWaiter
}

func NewDialBacks(logger *slog.Logger) *DialBacks {
	return &DialBacks{logger: logger, waiting: map[string]*dialWaiter{}}
}

func (d *DialBacks) Await(ctx context.Context, token, tunnel string, open func(context.Context) error) (net.Conn, error) {
	w := &dialWaiter{tunnel: tunnel, conn: make(chan net.Conn, 1)}
	d.mu.Lock()
	if _, dup := d.waiting[token]; dup {
		d.mu.Unlock()
		return nil, ErrDuplicateToken
	}
	d.waiting[token] = w
	d.mu.Unlock()
	defer d.abandon(token, w)
	if err := open(ctx); err != nil {
		return nil, fmt.Errorf("request OPEN for %s: %w", tunnel, err)
	}
	select {
	case c := <-w.conn:
		return c, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("await dial-back for %s: %w", tunnel, ctx.Err())
	}
}

func (d *DialBacks) abandon(token string, w *dialWaiter) {
	d.mu.Lock()
	if d.waiting[token] == w {
		delete(d.waiting, token)
	}
	d.mu.Unlock()
	select {
	case c := <-w.conn:
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			d.logger.Debug("abandoned dial-back close failed", "tunnel", w.tunnel, "err", err)
		}
	default:
	}
}

func (d *DialBacks) expects(token, tunnel string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.waiting[token]
	return ok && (tunnel == "" || w.tunnel == tunnel)
}

func (d *DialBacks) deliver(token, tunnel string, c net.Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.waiting[token]
	if !ok || (tunnel != "" && w.tunnel != tunnel) {
		return false
	}
	delete(d.waiting, token)
	w.conn <- c
	return true
}

func (h *Handler) serveDialBack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.Header.Get(wire.DialTokenHeader)
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || token == "" || !strings.EqualFold(r.Header.Get("Upgrade"), wire.DialUpgrade) {
		http.Error(w, "bad dial-back request", http.StatusBadRequest)
		return
	}
	tunnel := ""
	if h.dialBackMTLS {
		id, ok := h.identity(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if h.banTunnel != nil && h.banTunnel(id.name, id.fingerprint) {
			h.reject("ban", id.name, peerIP(r))
			http.Error(w, "banned", http.StatusForbidden)
			return
		}
		tunnel = id.name
	}
	if !h.dialBacks.expects(token, tunnel) {
		http.Error(w, "no such dial-back", http.StatusNotFound)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		h.mgr.logger.Warn("dial-back hijack failed", "tunnel", tunnel, "err", err)
		return
	}
	if err := upgradeDialBack(conn, brw); err != nil {
		h.mgr.logger.Debug("dial-back upgrade failed", "tunnel", tunnel, "err", err)
		h.closeDialBack(conn, tunnel)
		return
	}
	if !h.dialBacks.deliver(token, tunnel, &bufferedConn{Conn: conn, r: brw.Reader}) {
		h.closeDialBack(conn, tunnel)
	}
}

func upgradeDialBack(conn net.Conn, brw *bufio.ReadWriter) error {
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear dial-back deadlines: %w", err)
	}
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + wire.DialUpgrade + "\r\n\r\n"); err != nil {
		return fmt.Errorf("write dial-back 101: %w", err)
	}
	if err := brw.Flush(); err != nil {
		return fmt.Errorf("flush dial-back 101: %w", err)
	}
	return nil
}

func (h *Handler) closeDialBack(c net.Conn, tunnel string) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		h.mgr.logger.Debug("dial-back close failed", "tunnel", tunnel, "err", err)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
