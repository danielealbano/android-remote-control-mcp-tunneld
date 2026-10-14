package edge

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// rollingWindow is the window over which the connection-policy byte rate is measured (the --limit-conn-*
// min-rate and protect-rate thresholds are per-window). Overridden by tests to observe the min-rate kill
// without a real-time wait.
var rollingWindow = time.Minute

var routeCheckInterval = 10 * time.Second

// activeStream tracks a live public stream for the connection policy (idle timeout, min-rate, and
// eviction-on-saturation ranking).
type activeStream struct {
	tunnel     string
	member     string
	connID     string
	parent     context.Context
	fp         string       // the route fingerprint this stream targets (ban sweeps match on it)
	lastAct    atomic.Int64 // unix nanos of last byte activity
	recent     atomic.Int64 // bytes in the current rolling window
	started    time.Time
	cancel     context.CancelFunc
	evicted    atomic.Bool // set BEFORE cancel() on saturation eviction, so the splice can tell an eviction cancel from a server-drain (parent ctx) cancel
	banned     atomic.Bool // set BEFORE cancel() on a ban reload, so the splice attributes ban-evict over terminated/evicted/shutdown
	terminated atomic.Bool // set BEFORE cancel() on an admin terminate, so the splice attributes admin-terminate over evicted/shutdown
	phoneGone  atomic.Bool
	release    func() // frees this stream's global slot exactly once
	bytesIn    int64
	bytesOut   int64
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

// EvictTunnelStreams cancels every ACTIVE public splice for the named tunnel (admin terminate) on THIS
// node, attributing admin-terminate.
func (e *Edge) EvictTunnelStreams(name string) {
	e.smu.Lock()
	var victims []*activeStream
	for s := range e.streams {
		if s.tunnel == name {
			victims = append(victims, s)
		}
	}
	e.smu.Unlock()
	for _, s := range victims {
		s.terminated.Store(true)
		s.cancel()
	}
}

func (e *Edge) EvictConnStreams(name, connID, reason string) bool {
	e.smu.Lock()
	var victims []*activeStream
	for s := range e.streams {
		if s.tunnel == name && s.connID == connID {
			victims = append(victims, s)
		}
	}
	e.smu.Unlock()
	for _, s := range victims {
		switch reason {
		case store.CloseBanEvict:
			s.banned.Store(true)
		case store.CloseAdminTerminate:
			s.terminated.Store(true)
		default:
			s.phoneGone.Store(true)
		}
		s.cancel()
	}
	return len(victims) > 0
}

// handleTunnel resolves the route, enforces the ban + global stream cap (with one evict-and-retry),
// opens the far side, and splices with accounting + policy + conn logs.
func (e *Edge) handleTunnel(ctx context.Context, client net.Conn, info ClientHelloInfo) {
	name, ok := e.tunnelName(info.SNI)
	if !ok {
		e.rec.Reject("no-route", info.SNI, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}
	nodeID, fp, connID, ok, err := e.router.LookupRoute(ctx, name)
	if err != nil {
		e.cfg.Logger.Debug("route lookup failed", "tunnel", name, "err", err)
	}
	if err != nil || !ok {
		e.rec.Reject("no-route", name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}
	if e.banTun != nil && e.banTun(name, fp) {
		e.rec.Reject("ban", name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}

	// Admission-time quota gate: an exhausted day/week window refuses every NEW stream (in-flight
	// streams are closed by the splice's Charge accounting). A control-plane error fails open,
	// like connRate — never a hard outage.
	dayOver, weekOver, qerr := e.lim.TrafficExhausted(ctx, name)
	if qerr != nil {
		e.cfg.Logger.Debug("traffic quota check failed (allowing)", "tunnel", name, "err", qerr)
	}
	if qerr == nil && (dayOver || weekOver) {
		reason := "quota-day"
		if weekOver {
			reason = "quota-week"
		}
		e.rec.Reject(reason, name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}

	token := rand.Text()

	// Global per-tunnel stream cap with one evict-and-retry. A control-plane ERROR fails open (like
	// connRate/pace/quota): a Valkey blip must neither evict a healthy live stream nor refuse admission.
	acq, aerr := e.lim.AcquireStream(ctx, name, token, e.cfg.Concurrent)
	if aerr != nil {
		e.cfg.Logger.Debug("stream-cap acquire failed (allowing)", "tunnel", name, "err", aerr)
		acq = true
	} else if !acq && e.evictLeastActive(name) {
		acq, aerr = e.lim.AcquireStream(ctx, name, token, e.cfg.Concurrent)
		if aerr != nil {
			e.cfg.Logger.Debug("stream-cap acquire failed (allowing)", "tunnel", name, "err", aerr)
			acq = true
		}
	}
	if !acq {
		e.rec.Reject("stream-cap", name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}
	// Release-once: fires at most once (the saturation evictor releases the victim's slot
	// synchronously so the retry can admit).
	var slotOnce sync.Once
	releaseSlot := func() {
		slotOnce.Do(func() {
			if err := e.lim.ReleaseStream(context.Background(), name, token); err != nil {
				e.cfg.Logger.Debug("stream-cap release failed", "tunnel", name, "err", err)
			}
		})
	}
	defer releaseSlot()

	// Open the far side. On failure take ONE fresh route lookup — the route may have re-bound to a new
	// owner/connID while we held stale values (one fresh route lookup + retry, then
	// close) — and retry once when the fresh route differs (re-checking the ban on its fingerprint).
	openedVia := connID
	far, ferr := e.openFar(ctx, name, nodeID, connID, token)
	if ferr != nil {
		n2, fp2, c2, ok2, lerr := e.router.LookupRoute(ctx, name)
		if lerr != nil {
			e.cfg.Logger.Debug("route re-lookup failed", "tunnel", name, "err", lerr)
		}
		if lerr == nil && ok2 && (n2 != nodeID || c2 != connID) {
			if e.banTun != nil && e.banTun(name, fp2) {
				e.rec.Reject("ban", name, peerAddr(client))
				closeLogged(e.cfg.Logger, "public client", client)
				return
			}
			fp = fp2 // the splice now targets the re-bound route: the active stream must carry ITS fingerprint (ban sweeps match on it)
			openedVia = c2
			far, ferr = e.openFar(ctx, name, n2, c2, token)
		}
	}
	if ferr != nil {
		e.cfg.Logger.Debug("open far side failed", "tunnel", name, "err", ferr)
		e.rec.Reject("no-route", name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}
	defer closeLogged(e.cfg.Logger, "phone dial-back", far)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	as := &activeStream{tunnel: name, member: token, connID: openedVia, parent: ctx, fp: fp, started: e.now(), cancel: cancel}
	as.release = releaseSlot
	as.lastAct.Store(e.now().UnixNano())
	e.trackStream(as)
	defer e.untrackStream(as)

	// A ban reload during the dial-back wait sweeps only TRACKED streams; re-check now that we are
	// tracked so a tunnel banned in that window does not keep one live splice (docs/PROJECT.md §2 — a
	// reload stops live traffic, not only new admissions). The deferred untrackStream/slot
	// release run on this early return, and the client socket is closed like every sibling rejection.
	if e.banTun != nil && e.banTun(name, fp) {
		e.rec.Reject("ban", name, peerAddr(client))
		closeLogged(e.cfg.Logger, "public client", client)
		return
	}

	e.rec.PublicConnOpen()
	e.rec.StreamOpen()
	srcIP, srcPort := splitAddr(client.RemoteAddr())
	ev := PublicEvent{Conn: store.MustConnID(), Tunnel: name, Event: "start", SrcIP: srcIP, SrcPort: srcPort,
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
	closeLogged(e.cfg.Logger, "public client", client)
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

func (e *Edge) openFar(ctx context.Context, name, nodeID, connID, token string) (net.Conn, error) {
	timeout := e.cfg.DialBackTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	octx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return e.dialBacks.Await(octx, token, name, func(ctx context.Context) error {
		return e.opener.Open(ctx, nodeID, name, connID, token)
	})
}

// splice copies bytes both directions with byte accounting (day/week traffic) + bandwidth pacing +
// connection policy (idle timeout + min-rate kill past grace), returning the close reason. It waits for
// BOTH copy goroutines to exit before returning (so no goroutine touches the stream or the byte counters
// after handleTunnel reads them); a watcher closes both sides on ctx-cancel (eviction), idle timeout, a
// sub-min-rate connection, or a route that no longer carries this connection, which unblocks the copies.
func (e *Edge) splice(ctx context.Context, name string, client net.Conn, far io.ReadWriteCloser, as *activeStream) string {
	var reasonOnce sync.Once
	reason := store.CloseClientClose
	setReason := func(r string) { reasonOnce.Do(func() { reason = r }) }
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			closeLogged(e.cfg.Logger, "far side", far)
			closeLogged(e.cfg.Logger, "public client", client)
		})
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
	// phone → client (out): the source is the phone.
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

	// Policy watcher: closes both sides on eviction (ctx cancel), idle timeout, a sub-min-rate
	// connection past grace, or a route that no longer carries this connection, then exits; otherwise it exits once signalled after both copies finish. It
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
		nextRouteCheck := e.now().UnixNano() + int64(routeCheckInterval)
		for {
			select {
			case <-stopWatch:
				return
			case <-ctx.Done():
				// The stream ctx cancels on a ban reload (EvictBannedStreams marks banned first), on an
				// admin terminate (EvictTunnelStreams marks terminated first), on the close of the phone
				// control connection it was opened through (EvictConnStreams marks phoneGone first), on
				// saturation eviction (evictLeastActive marks evicted first), OR on server drain (the parent
				// ctx) — attribute each accurately, banned taking precedence.
				if as.banned.Load() {
					setReason(store.CloseBanEvict)
				} else if as.terminated.Load() {
					setReason(store.CloseAdminTerminate)
				} else if as.phoneGone.Load() && as.parent.Err() == nil {
					setReason(store.ClosePhoneClose)
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
				if now >= nextRouteCheck {
					nextRouteCheck = now + int64(routeCheckInterval)
					if _, _, cur, ok, lerr := e.router.LookupRoute(ctx, name); lerr != nil {
						e.cfg.Logger.Debug("splice route check failed (keeping the splice)", "tunnel", name, "err", lerr)
					} else if !ok || cur != as.connID {
						setReason(store.ClosePhoneClose)
						closeBoth()
						return
					}
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
			if action, wait, win, cerr := e.lim.Charge(ctx, name, as.member, dir, int64(nr)); cerr != nil {
				e.cfg.Logger.Debug("traffic charge failed (proceeding)", "tunnel", name, "dir", dir, "err", cerr)
			} else {
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
				e.cfg.Logger.Debug("splice write failed", "tunnel", name, "dir", dir, "err", ew)
				return copyWriteErr
			}
			atomic.AddInt64(counter, int64(nr))
			e.rec.Bytes(name, dir, int64(nr))
			as.lastAct.Store(e.now().UnixNano())
			as.recent.Add(int64(nr))
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				e.cfg.Logger.Debug("splice read ended with an error", "tunnel", name, "dir", dir, "err", er)
			}
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
