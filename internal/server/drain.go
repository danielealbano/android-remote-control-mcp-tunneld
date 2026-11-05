package server

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"
)

const (
	phaseServing int32 = iota
	phaseStopping
	phaseDraining
)

type lifecycle struct{ phase atomic.Int32 }

func (l *lifecycle) Stopping() bool { return l.phase.Load() >= phaseStopping }
func (l *lifecycle) Draining() bool { return l.phase.Load() >= phaseDraining }

type drainPhones interface {
	StartDrain(addrs []string)
	RetryMoves()
	LiveConns() int
}

type drainEdge interface {
	InFlightConns() int64
}

type drainIssues interface {
	InFlightIssues() int64
}

const (
	drainPoll       = 250 * time.Millisecond
	moveListTimeout = 5 * time.Second
)

type drainer struct {
	life     *lifecycle
	phones   drainPhones
	edge     drainEdge
	issues   drainIssues
	nodes    liveNodeLister
	nodeID   string
	predrain time.Duration
	grace    time.Duration
	poll     time.Duration
	logger   *slog.Logger
}

func (d *drainer) run(ctx context.Context) {
	d.life.phase.Store(phaseStopping)
	d.logger.Info("stopping: the health check now reports this node as unavailable", "predrain_wait", d.predrain)
	if !waitCtx(ctx, d.predrain) {
		return
	}
	addrs := d.moveTargets(ctx)
	d.life.phase.Store(phaseDraining)
	d.phones.StartDrain(addrs)
	if len(addrs) == 0 {
		d.logger.Info("draining: no other node is known, so the phones are not told where to move", "targets", addrs, "phones", d.phones.LiveConns(), "grace", d.grace)
	} else {
		d.logger.Info("draining: telling the phones to move to other nodes", "targets", addrs, "phones", d.phones.LiveConns(), "grace", d.grace)
	}
	deadline := time.NewTimer(d.grace)
	defer deadline.Stop()
	tick := time.NewTicker(d.poll)
	defer tick.Stop()
	for {
		if d.phones.LiveConns() == 0 && d.edge.InFlightConns() == 0 && d.issues.InFlightIssues() == 0 {
			d.logger.Info("drain finished: no phone connection, no public connection and no issuance left")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			d.logger.Info("the drain time ran out; stopping and closing what remains", "phones", d.phones.LiveConns(), "public_connections", d.edge.InFlightConns(),
				"issuances", d.issues.InFlightIssues())
			return
		case <-tick.C:
			d.phones.RetryMoves()
		}
	}
}

func (d *drainer) moveTargets(ctx context.Context) []string {
	lctx, cancel := context.WithTimeout(ctx, moveListTimeout)
	defer cancel()
	nodes, err := d.nodes.LiveNodes(lctx)
	if err != nil {
		d.logger.Warn("could not list the other nodes, so the phones are not told where to move; they reconnect when this node stops", "err", err)
		return nil
	}
	var out []string
	for id, n := range nodes {
		if id == d.nodeID {
			continue
		}
		out = append(out, n.Public)
	}
	slices.Sort(out)
	return out
}

func waitCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
