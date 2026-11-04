package server

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

type fakeDrainPhones struct {
	mu       sync.Mutex
	started  bool
	addrs    []string
	live     atomic.Int64
	retries  atomic.Int64
	life     *lifecycle
	sawDrain bool
}

func (f *fakeDrainPhones) StartDrain(addrs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
	f.addrs = addrs
	f.sawDrain = f.life.Draining()
}

func (f *fakeDrainPhones) LiveConns() int { return int(f.live.Load()) }

func (f *fakeDrainPhones) RetryMoves() { f.retries.Add(1) }

func (f *fakeDrainPhones) drain() (bool, []string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started, f.addrs, f.sawDrain
}

type fakeDrainEdge struct{ tunnels, issues atomic.Int64 }

func (f *fakeDrainEdge) InFlightConns() int64  { return f.tunnels.Load() }
func (f *fakeDrainEdge) InFlightIssues() int64 { return f.issues.Load() }

func newTestDrainer(nodes liveNodeLister, predrain, grace time.Duration) (*drainer, *fakeDrainPhones, *fakeDrainEdge) {
	life := &lifecycle{}
	phones := &fakeDrainPhones{life: life}
	ed := &fakeDrainEdge{}
	return &drainer{life: life, phones: phones, edge: ed, issues: ed, nodes: nodes, nodeID: "self",
		predrain: predrain, grace: grace, poll: 10 * time.Millisecond, logger: testLogger()}, phones, ed
}

func runDrain(ctx context.Context, d *drainer) <-chan struct{} {
	done := make(chan struct{})
	go func() { defer close(done); d.run(ctx) }()
	return done
}

func waitDrain(t *testing.T, done <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("the drain did not end within %s", within)
	}
}

func TestDrainer_MoveTargetsAreEveryOtherNode(t *testing.T) {
	t.Parallel()
	nodes := fakeLiveNodes{nodes: map[string]router.NodeInfo{
		"self": {Advertise: "10.0.0.1:9443", Public: "203.0.113.1:443"},
		"b":    {Advertise: "10.0.0.2:9443", Public: "203.0.113.2:443"},
		"c":    {Advertise: "10.0.0.3:9443", Public: "203.0.113.3:443"},
	}}
	d, phones, _ := newTestDrainer(nodes, 0, time.Second)
	waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
	started, addrs, sawDrain := phones.drain()
	if !started {
		t.Fatal("StartDrain was never called")
	}
	if !slices.Equal(addrs, []string{"203.0.113.2:443", "203.0.113.3:443"}) {
		t.Fatalf("MOVE targets = %v, want the other nodes' public addresses", addrs)
	}
	if !sawDrain {
		t.Fatal("the node must be draining before the phones are told to move")
	}
}

func TestDrainer_NodeListingErrorSendsNoMove(t *testing.T) {
	t.Parallel()
	d, phones, _ := newTestDrainer(fakeLiveNodes{err: errors.New("valkey down")}, 0, time.Second)
	waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
	started, addrs, _ := phones.drain()
	if !started || len(addrs) != 0 {
		t.Fatalf("StartDrain = (%v, %v), want called with no target", started, addrs)
	}
	if !d.life.Draining() {
		t.Fatal("the node must still drain when the node listing fails")
	}
}

func TestDrainer_LogsWhetherThePhonesAreToldWhereToMove(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		nodes liveNodeLister
		want  string
	}{
		{name: "other nodes", nodes: fakeLiveNodes{nodes: map[string]router.NodeInfo{
			"self": {Advertise: "10.0.0.1:9443", Public: "203.0.113.1:443"},
			"b":    {Advertise: "10.0.0.2:9443", Public: "203.0.113.2:443"},
		}}, want: `msg="draining: telling the phones to move to other nodes"`},
		{name: "this node only", nodes: fakeLiveNodes{nodes: map[string]router.NodeInfo{
			"self": {Advertise: "10.0.0.1:9443", Public: "203.0.113.1:443"},
		}}, want: `msg="draining: no other node is known, so the phones are not told where to move"`},
		{name: "node listing error", nodes: fakeLiveNodes{err: errors.New("valkey down")},
			want: `msg="draining: no other node is known, so the phones are not told where to move"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, _, _ := newTestDrainer(tc.nodes, 0, time.Second)
			buf := &syncBuffer{}
			d.logger = slog.New(slog.NewTextHandler(buf, nil))
			waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
			if out := buf.String(); !strings.Contains(out, "level=INFO "+tc.want) {
				t.Fatalf("want %s at Info; log = %q", tc.want, out)
			}
		})
	}
}

func TestDrainer_PredrainAnswersStoppingBeforeDraining(t *testing.T) {
	t.Parallel()
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, time.Hour, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := runDrain(ctx, d)
	deadline := time.Now().Add(5 * time.Second)
	for !d.life.Stopping() {
		if time.Now().After(deadline) {
			t.Fatal("the node never reported stopping")
		}
		time.Sleep(time.Millisecond)
	}
	if d.life.Draining() {
		t.Fatal("the node must not drain during the pre-drain wait")
	}
	if started, _, _ := phones.drain(); started {
		t.Fatal("no MOVE may be sent during the pre-drain wait")
	}
	cancel()
	waitDrain(t, done, 5*time.Second)
}

func TestDrainer_DrainStartsAfterThePredrain(t *testing.T) {
	t.Parallel()
	const predrain = 300 * time.Millisecond
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, predrain, time.Second)
	start := time.Now()
	waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
	if took := time.Since(start); took < predrain {
		t.Fatalf("the drain ended %s after the stop, before the %s pre-drain wait", took, predrain)
	}
	if started, _, _ := phones.drain(); !started || !d.life.Draining() {
		t.Fatal("the node must drain after the pre-drain wait")
	}
}

func TestDrainer_RetriesUnqueuedMovesWhileDraining(t *testing.T) {
	t.Parallel()
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, 0, 200*time.Millisecond)
	phones.live.Store(1)
	waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
	if n := phones.retries.Load(); n == 0 {
		t.Fatal("the drain must retry the MOVEs that could not be queued")
	}
}

func TestDrainer_CancelDuringPredrainSkipsTheDrain(t *testing.T) {
	t.Parallel()
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := runDrain(ctx, d)
	cancel()
	waitDrain(t, done, 5*time.Second)
	if started, _, _ := phones.drain(); started || d.life.Draining() {
		t.Fatal("a cancelled pre-drain must not start the drain")
	}
}

func TestDrainer_EndsEarlyWhenNothingIsLeft(t *testing.T) {
	t.Parallel()
	d, phones, ed := newTestDrainer(fakeLiveNodes{}, 0, time.Hour)
	phones.live.Store(1)
	ed.tunnels.Store(1)
	done := runDrain(context.Background(), d)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the drain must wait while a phone connection and a public connection remain")
	default:
	}
	phones.live.Store(0)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the drain must wait while a public connection remains")
	default:
	}
	ed.tunnels.Store(0)
	waitDrain(t, done, 5*time.Second)
}

func TestDrainer_InFlightIssuanceHoldsTheDrain(t *testing.T) {
	t.Parallel()
	d, _, ed := newTestDrainer(fakeLiveNodes{}, 0, time.Hour)
	ed.issues.Store(1)
	done := runDrain(context.Background(), d)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the drain must wait while an issuance is in flight")
	default:
	}
	ed.issues.Store(0)
	waitDrain(t, done, 5*time.Second)
}

func TestDrainer_GraceBoundsTheDrain(t *testing.T) {
	t.Parallel()
	const grace = 200 * time.Millisecond
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, 0, grace)
	phones.live.Store(1)
	start := time.Now()
	waitDrain(t, runDrain(context.Background(), d), 5*time.Second)
	if took := time.Since(start); took < grace {
		t.Fatalf("the drain ended after %s, before its %s grace", took, grace)
	}
}

func TestDrainer_CancelEndsTheDrain(t *testing.T) {
	t.Parallel()
	d, phones, _ := newTestDrainer(fakeLiveNodes{}, 0, time.Hour)
	phones.live.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	done := runDrain(ctx, d)
	time.Sleep(50 * time.Millisecond)
	cancel()
	waitDrain(t, done, 5*time.Second)
}

func TestLifecycle_Phases(t *testing.T) {
	t.Parallel()
	var l lifecycle
	if l.Stopping() || l.Draining() {
		t.Fatal("a new node is serving")
	}
	l.phase.Store(phaseStopping)
	if !l.Stopping() || l.Draining() {
		t.Fatal("stopping must not be draining")
	}
	l.phase.Store(phaseDraining)
	if !l.Stopping() || !l.Draining() {
		t.Fatal("draining is also stopping")
	}
}
