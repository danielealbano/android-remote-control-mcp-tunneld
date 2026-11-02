//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type busySplice struct {
	mu   sync.Mutex
	err  error
	stop chan struct{}
	done chan struct{}
	conn *tls.Conn
}

func keepBusy(conn *tls.Conn) *busySplice {
	b := &busySplice{stop: make(chan struct{}), done: make(chan struct{}), conn: conn}
	go func() {
		defer close(b.done)
		buf := make([]byte, 1)
		for {
			select {
			case <-b.stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
			_, err := conn.Write([]byte("k"))
			if err == nil {
				_, err = io.ReadFull(conn, buf)
			}
			if err != nil {
				b.mu.Lock()
				b.err = err
				b.mu.Unlock()
				return
			}
		}
	}()
	return b
}

func (b *busySplice) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *busySplice) close() {
	select {
	case <-b.stop:
	default:
		close(b.stop)
	}
	tunneltest.CloseLogged(b.conn)
	<-b.done
}

func TestE2E_DrainMovesThePhoneAndKeepsInFlightConnections(t *testing.T) {
	inf := startE2EInfra(t)
	edgeA := inf.startReplica(t, replicaOpts{connIdle: 30 * time.Second})
	edgeB := inf.startReplica(t, replicaOpts{connIdle: 30 * time.Second})
	_, ident, runDone := echoPhoneRun(t, inf, edgeA, edgeA)
	fqdn := ident.Name + "." + e2eTunnelDomain
	ctx := context.Background()

	reg := e2eRegistry(t, inf)
	var rtErr error
	if !waitBool(30*time.Second, func() bool {
		rtErr = frontendRoundtrip(edgeA, fqdn, inf.pebble.IssuingRoots)
		return rtErr == nil
	}) {
		t.Fatalf("route never bound on replica A: %v", rtErr)
	}
	nodeA, _, ok, err := reg.LookupRoute(ctx, ident.Name)
	if err != nil || !ok {
		t.Fatalf("route lookup: ok=%v err=%v", ok, err)
	}

	live, err := dialTunnelTLS(edgeA, fqdn, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("open a live splice through A: %v", err)
	}
	defer tunneltest.CloseLogged(live)
	if err := live.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := echoOn(live); err != nil {
		t.Fatalf("the live splice through A does not echo: %v", err)
	}
	busy := keepBusy(live)
	defer busy.close()

	stopped := make(chan error, 1)
	stopAt := time.Now()
	go func() { stopped <- inf.stop[edgeA]() }()

	var lookupErr error
	if !waitBool(10*time.Second, func() bool {
		var node string
		node, _, ok, lookupErr = reg.LookupRoute(ctx, ident.Name)
		return lookupErr == nil && ok && node != nodeA
	}) {
		t.Fatalf("the phone must move to replica B when A drains (last lookup error: %v)", lookupErr)
	}
	movedAfter := time.Since(stopAt)
	for _, edge := range []string{edgeB, edgeA} {
		if err := frontendRoundtrip(edge, fqdn, inf.pebble.IssuingRoots); err != nil {
			t.Fatalf("a public connection through %s during A's drain must reach the moved phone: %v", edge, err)
		}
	}

	_, second, _ := echoPhoneRun(t, inf, edgeB, edgeA)
	secondFQDN := second.Name + "." + e2eTunnelDomain
	var secondNode string
	if !waitBool(10*time.Second, func() bool {
		var bound bool
		secondNode, _, bound, lookupErr = reg.LookupRoute(ctx, second.Name)
		return lookupErr == nil && bound
	}) {
		t.Fatalf("a phone connecting to the draining replica must bind elsewhere (last lookup error: %v)", lookupErr)
	}
	if secondNode == nodeA {
		t.Fatal("a draining replica must not register the route of a new control connection")
	}
	if err := frontendRoundtrip(edgeB, secondFQDN, inf.pebble.IssuingRoots); err != nil {
		t.Fatalf("a phone moved by the draining replica's answer must be reachable through B: %v", err)
	}

	time.Sleep(12 * time.Second)
	if err := busy.failure(); err != nil {
		t.Fatalf("the splice through A that was in flight before the move must survive the route check: %v", err)
	}

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("replica A stop: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("replica A did not stop after its drain")
	}
	t.Logf("the phone moved %s after the stop; replica A stopped %s after it", movedAfter, time.Since(stopAt))
	if !waitBool(5*time.Second, func() bool { return busy.failure() != nil }) {
		t.Fatal("the splice through A must end when A stops")
	}
	if err := busy.failure(); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the splice through A must be closed by A, not time out: %v", err)
	}
	if err := frontendRoundtrip(edgeB, fqdn, inf.pebble.IssuingRoots); err != nil {
		t.Fatalf("after A stopped, the phone must still be reachable through B: %v", err)
	}
	select {
	case <-runDone:
		t.Fatal("the phone's client must keep running on B after A stopped")
	default:
	}
}
