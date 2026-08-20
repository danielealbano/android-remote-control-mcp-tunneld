package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// rollingWindow is the window over which the connection-policy byte rate is measured (the --limit-conn-*
// min-rate and protect-rate thresholds are per-window). Overridden by tests to observe the min-rate kill
// without a real-time wait.
var rollingWindow = time.Minute

// activeStream tracks a live public stream for the connection policy (idle timeout, min-rate, and
// eviction-on-saturation ranking).
type activeStream struct {
	tunnel   string
	fp       string       // the route fingerprint this stream targets (ban sweeps match on it)
	lastAct  atomic.Int64 // unix nanos of last byte activity
	recent   atomic.Int64 // bytes in the current rolling window
	started  time.Time
	cancel   context.CancelFunc
	evicted  atomic.Bool // set BEFORE cancel() on saturation eviction, so the splice can tell an eviction cancel from a server-drain (parent ctx) cancel
	banned   atomic.Bool // set BEFORE cancel() on a ban reload, so the splice attributes ban-evict over evicted/shutdown
	release  func()      // frees this stream's global slot exactly once; a no-op when no slot was actually acquired (fail-open)
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
		victim.evicted.Store(true)
		victim.cancel()
		if victim.release != nil {
			victim.release() // free the Valkey slot NOW; the victim's own deferred release becomes a no-op
		}
		return true
	}
	return false
}

// EvictBannedStreams cancels every ACTIVE public splice whose (tunnel, fingerprint) matches: bans are
// the ONLY revocation, so a reload must stop in-flight traffic, not only new admissions.
func (e *Edge) EvictBannedStreams(match func(name, fingerprint string) bool) {
	e.smu.Lock()
	var victims []*activeStream
	for s := range e.streams {
		if match(s.tunnel, s.fp) {
			victims = append(victims, s)
		}
	}
	e.smu.Unlock()
	for _, s := range victims {
		s.banned.Store(true)
		s.cancel()
	}
}

// handleTunnel resolves the route, enforces the ban + global stream cap (with one evict-and-retry),
// opens the far side (local fast path or mesh), and splices with accounting + policy + conn logs.
func (e *Edge) handleTunnel(ctx context.Context, client net.Conn, info ClientHelloInfo) {
	name, ok := e.tunnelName(info.SNI)
	if !ok {
		e.rec.Reject("no-route", info.SNI, peerAddr(client))
		_ = client.Close()
		return
	}
	nodeID, fp, connID, ok, err := e.router.LookupRoute(ctx, name)
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

	// Admission-time quota gate: an exhausted day/week window refuses every NEW stream (in-flight
	// streams are closed by the splice's Charge accounting). A control-plane error fails open,
	// like connRate — never a hard outage.
	dayOver, weekOver, qerr := e.lim.TrafficExhausted(ctx, name)
	if qerr == nil && (dayOver || weekOver) {
		reason := "quota-day"
		if weekOver {
			reason = "quota-week"
		}
		e.rec.Reject(reason, name, peerAddr(client))
		_ = client.Close()
		return
	}

	// A stream id is required for the dial-back match: an EMPTY id would be 400-refused by serveData/mesh
	// and turn the connection into a no-route, so use the non-empty fallback on the (practically
	// impossible) crypto/rand failure rather than an empty id.
	streamID := store.MustConnID()

	// Global per-tunnel stream cap with one evict-and-retry. A control-plane ERROR fails open (like
	// connRate/pace/quota): a Valkey blip must neither evict a healthy live stream nor refuse admission.
	acq, aerr := e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
	if aerr != nil {
		acq = true
	} else if !acq && e.evictLeastActive(name) {
		acq, aerr = e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
		if aerr != nil {
			acq = true
		}
	}
	if !acq {
		e.rec.Reject("stream-cap", name, peerAddr(client))
		_ = client.Close()
		return
	}
	// Release-once: fires only when a slot was REALLY acquired (a fail-open admission must not DECR a
	// slot it never took) and at most once (the saturation evictor releases the victim's slot
	// synchronously so the retry can admit). The release error stays intentionally ignored: the global
	// conc:{name} counter self-heals at its TTL, so a transient Valkey failure at worst delays freeing
	// one slot — and there is no logger on the edge's hot path.
	slotHeld := aerr == nil
	var slotOnce sync.Once
	releaseSlot := func() {
		if slotHeld {
			slotOnce.Do(func() { _ = e.lim.ReleaseStream(context.Background(), name) })
		}
	}
	defer releaseSlot()

	// Open the far side. On failure take ONE fresh route lookup — the route may have re-bound to a new
	// owner/connID while we held stale values (docs/PROTOCOL.md §5: one fresh route lookup + retry, then
	// close) — and retry once when the fresh route differs (re-checking the ban on its fingerprint).
	far, closeFar, ferr := e.openFar(ctx, name, nodeID, connID, streamID)
	if isDuplicateStream(ferr) {
		streamID = store.MustConnID()
		far, closeFar, ferr = e.openFar(ctx, name, nodeID, connID, streamID)
	}
	if ferr != nil {
		n2, fp2, c2, ok2, lerr := e.router.LookupRoute(ctx, name)
		if lerr == nil && ok2 && (n2 != nodeID || c2 != connID) {
			if e.banTun != nil && e.banTun(name, fp2) {
				e.rec.Reject("ban", name, peerAddr(client))
				_ = client.Close()
				return
			}
			fp = fp2 // the splice now targets the re-bound route: the active stream must carry ITS fingerprint (ban sweeps match on it)
			streamID = store.MustConnID()
			far, closeFar, ferr = e.openFar(ctx, name, n2, c2, streamID)
		}
	}
	if ferr != nil {
		e.rec.Reject("no-route", name, peerAddr(client))
		_ = client.Close()
		return
	}
	defer closeFar()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	as := &activeStream{tunnel: name, fp: fp, started: e.now(), cancel: cancel}
	as.release = releaseSlot
	as.lastAct.Store(e.now().UnixNano())
	e.trackStream(as)
	defer e.untrackStream(as)

	// A ban reload during the dial-back wait sweeps only TRACKED streams; re-check now that we are
	// tracked so a tunnel banned in that window does not keep one live splice (docs/PROJECT.md §2 — a
	// reload stops live traffic, not only new admissions). The deferred untrackStream/closeFar/slot
	// release run on this early return, and the client socket is closed like every sibling rejection.
	if e.banTun != nil && e.banTun(name, fp) {
		e.rec.Reject("ban", name, peerAddr(client))
		_ = client.Close()
		return
	}

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
		end.BytesIn = atomic.LoadInt64(&as.bytesIn)
		end.BytesOut = atomic.LoadInt64(&as.bytesOut)
		e.logs.PutConnLogPublic(context.Background(), end)
	}
	_ = client.Close()
}

// isDuplicateStream reports whether opening the far side failed because the minted stream id was
// already pending on the owner's phone connection (local or mesh) — the edge re-mints once and retries.
func isDuplicateStream(err error) bool {
	return errors.Is(err, phoneconn.ErrDuplicateStreamID) || errors.Is(err, mesh.ErrDuplicateStream)
}

// tunnelName derives the bare tunnel name (the phone identity-cert CN, under which the route is bound)
// from a public SNI `<name>.<tunnel-domain>`. It rejects an SNI that is not a single label under the
// configured tunnel domain.
func (e *Edge) tunnelName(sni string) (string, bool) {
	sni = strings.ToLower(sni)
	suffix := "." + e.cfg.TunnelDomain
	if e.cfg.TunnelDomain == "" || !strings.HasSuffix(sni, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(sni, suffix)
	if name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

// openFar opens the phone data stream locally (fast path) or over the mesh. The local dial-back wait is
// bounded by --limit-dialback-timeout so a connected phone that never opens the /data stream fails fast
// and releases the stream slot rather than pinning it. On the mesh path the owner node bounds its own
// dial-back the same way (see server.bridgeAdapter.OpenMesh); the entry node's mesh dial returns once
// the owner has accepted, so this local timeout governs only the fast path.
func (e *Edge) openFar(ctx context.Context, name, nodeID, connID, streamID string) (io.ReadWriteCloser, func(), error) {
	if e.local != nil && e.local.HasConn(name) && e.local.OwnsConn(name, connID) {
		timeout := e.cfg.DialBackTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		octx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel() // bounds ONLY the dial-back wait; the returned stream does not depend on octx
		ds, err := e.local.OpenStream(octx, name, streamID)
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
// connection policy (idle timeout + min-rate kill past grace), returning the close reason. It waits for
// BOTH copy goroutines to exit before returning (so no goroutine touches the stream or the byte counters
// after handleTunnel reads them); a watcher closes both sides on ctx-cancel (eviction), idle timeout, or a
// sub-min-rate connection, which unblocks the copies.
func (e *Edge) splice(ctx context.Context, name string, client net.Conn, far io.ReadWriteCloser, as *activeStream) string {
	var reasonOnce sync.Once
	reason := store.CloseClientClose
	setReason := func(r string) { reasonOnce.Do(func() { reason = r }) }
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() { _ = far.Close(); _ = client.Close() })
	}

	done := make(chan struct{}, 2)
	// client → phone (in, from the peer's perspective): the source is the public client.
	go func() {
		switch e.pacedCopy(ctx, name, "in", far, client, as, &as.bytesIn) {
		case quotaHit:
			setReason(store.CloseQuotaExhausted)
		case copySrcEOF:
			setReason(store.CloseClientClose) // the public client closed its side
		case copyWriteErr:
			setReason(store.CloseError) // writing to the phone failed
		}
		done <- struct{}{}
	}()
	// phone → client (out): the source is the phone (local dial-back or mesh stream).
	go func() {
		switch e.pacedCopy(ctx, name, "out", client, far, as, &as.bytesOut) {
		case quotaHit:
			setReason(store.CloseQuotaExhausted)
		case copySrcEOF:
			setReason(store.ClosePhoneClose) // the phone closed its side
		case copyWriteErr:
			setReason(store.CloseError) // writing to the public client failed
		}
		done <- struct{}{}
	}()

	// Policy watcher: closes both sides on eviction (ctx cancel), idle timeout, or a sub-min-rate
	// connection past grace, then exits; otherwise it exits once signalled after both copies finish. It
	// maintains a true rolling-window (rollingWindow, ~60s) byte total from clock-stamped cumulative-byte
	// samples that feeds BOTH the min-rate kill here and the eviction protect-rate ranking (via as.recent).
	stopWatch := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		ticker := time.NewTicker(e.idlePoll())
		defer ticker.Stop()
		type sample struct{ t, bytes int64 }
		var samples []sample
		window := int64(rollingWindow)
		for {
			select {
			case <-stopWatch:
				return
			case <-ctx.Done():
				// The stream ctx cancels on a ban reload (EvictBannedStreams marks banned first), on
				// saturation eviction (evictLeastActive marks evicted first), OR on server drain (the
				// parent ctx) — attribute each accurately, banned taking precedence.
				if as.banned.Load() {
					setReason(store.CloseBanEvict)
				} else if as.evicted.Load() {
					setReason(store.CloseEvicted)
				} else {
					setReason(store.CloseServerShutdown)
				}
				closeBoth()
				return
			case <-ticker.C:
				now := e.now().UnixNano()
				if e.cfg.IdleTimeout > 0 && now-as.lastAct.Load() > int64(e.cfg.IdleTimeout) {
					setReason(store.CloseIdleTimeout)
					closeBoth()
					return
				}
				total := atomic.LoadInt64(&as.bytesIn) + atomic.LoadInt64(&as.bytesOut)
				samples = append(samples, sample{now, total})
				// Drop samples older than the window, keeping the newest one at-or-before the cutoff so
				// `rolling` measures bytes over exactly the last window.
				cutoff := now - window
				drop := 0
				for drop < len(samples)-1 && samples[drop+1].t <= cutoff {
					drop++
				}
				samples = samples[drop:]
				rolling := total - samples[0].bytes
				as.recent.Store(rolling)
				// Min-rate kill: once the connection is older than the window AND past the grace period, a
				// connection whose rolling-window traffic is below --limit-conn-min-rate is dropped
				// (slow-drip / slowloris guard). The window-age guard keeps `rolling` from under-counting a
				// young connection into a premature kill.
				age := now - as.started.UnixNano()
				if e.cfg.MinRate > 0 && age >= window && age > int64(e.cfg.MinGrace) && rolling < e.cfg.MinRate {
					setReason(store.CloseMinRate)
					closeBoth()
					return
				}
			}
		}
	}()

	<-done      // one direction finished (EOF, quota, or a closed side)
	closeBoth() // cascade the other direction
	<-done      // wait for it to exit before returning
	close(stopWatch)
	<-watchExited // all writers (copies + watcher) have stopped; reason is now safe to read
	return reason
}

// pacedCopy outcome codes: the source EOF'd (or was force-closed), a write to the destination failed,
// or the per-tunnel traffic quota was hit. The FIRST direction to finish sets the close reason (via the
// caller's reasonOnce); a subsequent force-closed direction's outcome is ignored.
const (
	copySrcEOF   = 0
	quotaHit     = -1
	copyWriteErr = -2
)

// pacedCopy copies src→dst in ≤ChunkSize (16 KiB) slices, charging each read against ALL per-window
// counters (per-second byte/packet + per-direction day/week traffic) in one unified Charge. Proceed →
// forward; Wait → pace out the rest of the (near) window then forward (that wait IS the pacing); Kill →
// a day/week cap is exhausted with its reset too far to wait out, so stop and return quotaHit. A
// control-plane error fails open (forward unpaced) so a live stream is never killed on a Valkey blip.
func (e *Edge) pacedCopy(ctx context.Context, name, dir string, dst io.Writer, src io.Reader, as *activeStream, counter *int64) int64 {
	buf := make([]byte, wire.ChunkSize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// One charge covers the per-second bandwidth windows AND the day/week traffic quotas. Proceed →
			// forward; Wait → pace out the rest of the (near) window then forward; Kill → the tunnel exceeded
			// a day/week cap whose reset is too far to wait out. A Valkey error yields Proceed (fail-open —
			// never kill a live stream on a control-plane blip).
			if action, wait, win, cerr := e.lim.Charge(ctx, name, dir, int64(nr)); cerr == nil {
				switch action {
				case limit.ChargeWait:
					select {
					case <-ctx.Done(): // teardown — abandon the wait, don't hold the copy hostage
					case <-time.After(wait):
					}
				case limit.ChargeKill:
					e.rec.QuotaExhausted(name, win)
					return quotaHit
				}
			}
			if _, ew := dst.Write(buf[:nr]); ew != nil {
				return copyWriteErr
			}
			atomic.AddInt64(counter, int64(nr))
			e.rec.Bytes(name, dir, int64(nr))
			as.lastAct.Store(e.now().UnixNano())
			as.recent.Add(int64(nr))
		}
		if er != nil {
			return copySrcEOF
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
