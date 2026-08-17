package wsconn

import (
	"context"
	"errors"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

// runHeartbeat refreshes the routing entry every --route-ttl/3. not-owner → the phone re-bound
// elsewhere (close as superseded, do NOT unbind the new node's route — the connID-conditional Unbind
// makes that safe anyway). missing → the TTL lapsed while the WS stayed healthy: self-heal by
// re-binding.
func (c *Conn) runHeartbeat() {
	interval := c.mgr.cfg.RouteTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if stop := c.heartbeatOnce(); stop {
				return
			}
		}
	}
}

// heartbeatOnce performs one heartbeat cycle and reports whether the loop should stop (the Conn was
// torn down). Split out for deterministic testing.
func (c *Conn) heartbeatOnce() (stop bool) {
	res, err := c.mgr.registry.Heartbeat(c.ctx, c.name, c.connID)
	if err != nil {
		return false
	}
	switch res {
	case router.HeartbeatRefreshed:
		return false
	case router.HeartbeatNotOwner:
		c.teardown("superseded")
		return true
	case router.HeartbeatMissing:
		return c.selfHeal()
	default:
		return false
	}
}

// selfHeal re-binds a route whose TTL lapsed while the WS stayed healthy, connID-conditionally: if the
// route is now owned by a DIFFERENT connID (same fingerprint) or a different fingerprint, this conn was
// superseded and must tear down rather than clobber the newer owner (docs/ARCHITECTURE.md §3). Reports
// whether the loop should stop. Split out for deterministic testing.
func (c *Conn) selfHeal() (stop bool) {
	res, err := c.mgr.registry.BindIfAbsentOrOwner(c.ctx, c.name, c.mgr.nodeID, c.fp, c.connID)
	switch {
	case res == router.SelfHealNotOwner || errors.Is(err, router.ErrNameHeldByOther):
		c.teardown("superseded")
		return true
	case err != nil:
		c.mgr.log.Warn("heartbeat self-heal bind failed", "tunnel", c.name, "err", err)
		return false
	default:
		return false
	}
}

// runKeepalive sends native WS control pings at --ping-interval; a failed ping means a dead peer.
func (c *Conn) runKeepalive() {
	ticker := time.NewTicker(c.mgr.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.teardown("dead_peer")
				return
			}
		}
	}
}
