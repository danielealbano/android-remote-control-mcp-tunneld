package edge

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// activeStream tracks a live public stream for the connection policy (idle timeout, min-rate, and
// eviction-on-saturation ranking).
type activeStream struct {
	tunnel   string
	lastAct  atomic.Int64 // unix nanos of last byte activity
	recent   atomic.Int64 // bytes in the current rolling window
	started  time.Time
	cancel   context.CancelFunc
	bytesIn  int64
	bytesOut int64
}

func (e *Edge) trackStream(s *activeStream) {
	e.smu.Lock()
	if e.streams == nil {
		e.streams = map[*activeStream]struct{}{}
	}
	e.streams[s] = struct{}{}
	e.smu.Unlock()
}

func (e *Edge) untrackStream(s *activeStream) {
	e.smu.Lock()
	delete(e.streams, s)
	e.smu.Unlock()
}

// evictLeastActive closes the least-active EVICTABLE local stream of a tunnel (idle ≥ EvictIdle OR
// rolling rate < ProtectRate; never a protected stream). Returns true if one was evicted.
func (e *Edge) evictLeastActive(tunnel string) bool {
	now := e.now().UnixNano()
	e.smu.Lock()
	var victim *activeStream
	var victimIdle int64 = -1
	for s := range e.streams {
		if s.tunnel != tunnel {
			continue
		}
		idle := now - s.lastAct.Load()
		rate := s.recent.Load()
		evictable := idle >= int64(e.cfg.EvictIdle) || rate < e.cfg.ProtectRate
		if !evictable {
			continue
		}
		if idle > victimIdle {
			victim = s
			victimIdle = idle
		}
	}
	e.smu.Unlock()
	if victim != nil {
		victim.cancel()
		return true
	}
	return false
}

// handleTunnel resolves the route, enforces the ban + global stream cap (with one evict-and-retry),
// opens the far side (local fast path or mesh), and splices with accounting + policy + conn logs.
func (e *Edge) handleTunnel(ctx context.Context, client net.Conn, info ClientHelloInfo) {
	name := info.SNI
	nodeID, fp, connID, startedAt, ok, err := e.router.LookupRoute(ctx, name)
	if err != nil || !ok {
		e.rec.Reject("no-route", name, peerAddr(client))
		_ = client.Close()
		return
	}
	if e.banTun != nil && e.banTun(name, fp) {
		e.rec.Reject("ban", name, peerAddr(client))
		_ = client.Close()
		return
	}

	streamID, _ := store.NewConnID(startedAt, e.now())

	// Global per-tunnel stream cap with one evict-and-retry.
	acq, _ := e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
	if !acq {
		if e.evictLeastActive(name) {
			acq, _ = e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
		}
	}
	if !acq {
		e.rec.Reject("stream-cap", name, peerAddr(client))
		_ = client.Close()
		return
	}
	defer func() { _ = e.lim.ReleaseStream(context.Background(), name) }()

	// Open the far side.
	far, closeFar, ferr := e.openFar(ctx, name, nodeID, connID, streamID)
	if ferr != nil {
		e.rec.Reject("no-route", name, peerAddr(client))
		_ = client.Close()
		return
	}
	defer closeFar()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	as := &activeStream{tunnel: name, started: e.now(), cancel: cancel}
	as.lastAct.Store(e.now().UnixNano())
	e.trackStream(as)
	defer e.untrackStream(as)

	e.rec.PublicConnOpen()
	e.rec.StreamOpen()
	srcIP, srcPort := splitAddr(client.RemoteAddr())
	ev := PublicEvent{Conn: streamID, Tunnel: name, Event: "start", SrcIP: srcIP, SrcPort: srcPort,
		SNI: info.SNI, ALPN: info.ALPN, TLSVersion: info.TLSVersion, JA4: info.JA4, StartedAt: as.started}
	if e.logs != nil {
		e.logs.PutConnLogPublic(ctx, ev)
	}

	reason := e.splice(sctx, name, client, far, as)

	e.rec.StreamClose()
	e.rec.PublicConnClose(reason)
	if e.logs != nil {
		end := ev
		end.Event = "end"
		end.CloseReason = reason
		end.EndedAt = e.now()
		end.BytesIn = as.bytesIn
		end.BytesOut = as.bytesOut
		e.logs.PutConnLogPublic(context.Background(), end)
	}
	_ = client.Close()
}

// openFar opens the phone data stream locally (fast path) or over the mesh.
func (e *Edge) openFar(ctx context.Context, name, nodeID, connID, streamID string) (io.ReadWriteCloser, func(), error) {
	if e.local != nil && e.local.HasConn(name) && e.local.OwnsConn(name, connID) {
		ds, err := e.local.OpenStream(ctx, name, streamID)
		if err != nil {
			return nil, nil, err
		}
		return ds, func() { _ = ds.Close() }, nil
	}
	// Mesh: resolve the owner's advertise address.
	adv, ok, err := e.router.LookupNode(ctx, nodeID)
	if err != nil || !ok {
		return nil, nil, errNoOwner
	}
	ms, err := e.mesh.OpenStream(ctx, adv, name, connID, streamID)
	if err != nil {
		return nil, nil, err
	}
	return ms, func() { _ = ms.Close() }, nil
}

// splice copies bytes both directions with byte accounting (day/week traffic) + bandwidth pacing +
// idle-timeout policy, returning the close reason.
func (e *Edge) splice(ctx context.Context, name string, client net.Conn, far io.ReadWriteCloser, as *activeStream) string {
	var once sync.Once
	reason := store.CloseClientClose
	setReason := func(r string) { once.Do(func() { reason = r }) }

	done := make(chan struct{}, 2)
	// client → phone (in, from the peer's perspective).
	go func() {
		n := e.pacedCopy(ctx, name, "in", far, client, as, &as.bytesIn)
		if n == quotaHit {
			setReason(store.CloseQuotaExhausted)
		}
		done <- struct{}{}
	}()
	// phone → client (out).
	go func() {
		n := e.pacedCopy(ctx, name, "out", client, far, as, &as.bytesOut)
		if n == quotaHit {
			setReason(store.CloseQuotaExhausted)
		}
		done <- struct{}{}
	}()

	idle := time.NewTicker(e.idlePoll())
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			setReason(store.CloseEvicted)
			_ = far.Close()
			_ = client.Close()
			return reason
		case <-done:
			_ = far.Close()
			_ = client.Close()
			return reason
		case <-idle.C:
			last := as.lastAct.Load()
			if e.cfg.IdleTimeout > 0 && e.now().UnixNano()-last > int64(e.cfg.IdleTimeout) {
				setReason(store.CloseIdleTimeout)
				_ = far.Close()
				_ = client.Close()
				return reason
			}
			as.recent.Store(0) // reset the rolling window
		}
	}
}

const quotaHit = -1

// pacedCopy copies src→dst in ≤ChunkSize slices, drawing bandwidth credits and accounting day/week
// traffic; on quota exhaustion it stops and returns quotaHit.
func (e *Edge) pacedCopy(ctx context.Context, name, dir string, dst io.Writer, src io.Reader, as *activeStream, counter *int64) int64 {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			e.pace(ctx, name, dir, int64(nr))
			dayOK, weekOK, _ := e.lim.ClaimTraffic(ctx, name, int64(nr))
			if !dayOK || !weekOK {
				win := "day"
				if !weekOK {
					win = "week"
				}
				e.rec.QuotaExhausted(name, win)
				return quotaHit
			}
			if _, ew := dst.Write(buf[:nr]); ew != nil {
				return 0
			}
			atomic.AddInt64(counter, int64(nr))
			e.rec.Bytes(name, dir, int64(nr))
			as.lastAct.Store(e.now().UnixNano())
			as.recent.Add(int64(nr))
		}
		if er != nil {
			return 0
		}
	}
}

// pace draws bandwidth credits for n bytes (best-effort; a control-plane error does not stall traffic).
func (e *Edge) pace(ctx context.Context, name, dir string, n int64) {
	remaining := n
	for remaining > 0 {
		granted, err := e.lim.ClaimBandwidth(ctx, name, dir, remaining)
		if err != nil || granted <= 0 {
			return // fail-open
		}
		remaining -= granted
		if remaining > 0 {
			// Wait a short slice for the bucket to refill rather than spinning.
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
}

func (e *Edge) idlePoll() time.Duration {
	if e.cfg.IdleTimeout > 0 && e.cfg.IdleTimeout < time.Second {
		return e.cfg.IdleTimeout
	}
	return time.Second
}

func splitAddr(a net.Addr) (string, int) {
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	p := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			break
		}
		p = p*10 + int(c-'0')
	}
	return host, p
}
