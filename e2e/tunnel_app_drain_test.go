//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"
)

func TestE2E_ReferenceTunnelAppMovesOnDrain(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	opts := attestedOpts("tunnel-app")
	opts.connIdle = 30 * time.Second
	opts.bandwidth = "100mbit"
	edgeA := inf.startReplica(t, opts)
	edgeB := inf.startReplica(t, opts)
	reverseVia(t, serial, edgeA)
	adbReverseSame(t, serial, edgeB)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	enrollTunnelApp(t, serial, caPath)
	name := readyName(t, serial, tunnelAppPkg)
	fqdn := name + "." + e2eTunnelDomain
	reg := e2eRegistry(t, inf)
	ctx := context.Background()
	roots := inf.pebble.IssuingRoots

	var infoErr error
	if !waitBool(60*time.Second, func() bool {
		_, infoErr = fetchInfo(edgeA, fqdn, roots)
		return infoErr == nil
	}) {
		t.Fatalf("/info through A never succeeded: %v", infoErr)
	}
	nodeA, _, bound, err := reg.LookupRoute(ctx, name)
	if err != nil || !bound {
		t.Fatalf("route lookup: ok=%v err=%v", bound, err)
	}

	inFlight := make(chan error, 1)
	go func() { inFlight <- waitOnce(h1Client(edgeA, fqdn, roots), fqdn, 15) }()
	time.Sleep(2 * time.Second)
	stopped := make(chan error, 1)
	go func() { stopped <- inf.stop[edgeA]() }()

	var lookupErr error
	if !waitBool(15*time.Second, func() bool {
		var node string
		node, _, bound, lookupErr = reg.LookupRoute(ctx, name)
		return lookupErr == nil && bound && node != nodeA
	}) {
		t.Fatalf("the app must move to replica B when A drains (last lookup error: %v)", lookupErr)
	}
	for _, edge := range []string{edgeB, edgeA} {
		if _, err := fetchInfo(edge, fqdn, roots); err != nil {
			t.Fatalf("/info through %s during A's drain: %v", edge, err)
		}
	}
	select {
	case err := <-inFlight:
		if err != nil {
			t.Fatalf("the /wait request in flight through A when it started draining must complete: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the in-flight /wait request never finished")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("replica A stop: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("replica A did not stop after its drain")
	}
	if _, err := fetchInfo(edgeB, fqdn, roots); err != nil {
		t.Fatalf("/info through B after A stopped: %v", err)
	}
}
