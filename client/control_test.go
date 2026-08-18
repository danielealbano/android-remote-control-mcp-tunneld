package client

import (
	"context"
	"io"
	"testing"
	"time"
)

// TestControlConnectBindAndDuplex covers: control connect + bind, dial-back opens a data stream, and a
// full-duplex splice (the echo backend proves interleaved read/write works across the data stream).
func TestControlConnectBindAndDuplex(t *testing.T) {
	ts := startTestServer(t)
	echo := func(s io.ReadWriteCloser) { _, _ = io.Copy(s, s) }
	c := ts.newClient(t, echo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// The control stream must bind the route (HasConn becomes true).
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}

	// Dial-back: OpenStream sends OPEN, the client opens the /data stream, deliverStream returns it.
	openCtx, openCancel := context.WithTimeout(ctx, 3*time.Second)
	defer openCancel()
	ds, err := ts.mgr.OpenStream(openCtx, testName, "stream-1")
	if err != nil {
		t.Fatalf("dial-back OpenStream failed: %v", err)
	}
	defer ds.Close()

	// Full-duplex echo: write client→phone bytes; the echo backend must send them back phone→client.
	msg := []byte("full-duplex-hello")
	if _, err := ds.Write(msg); err != nil {
		t.Fatalf("write to data stream: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(ds, buf); err != nil {
		t.Fatalf("read echo from data stream: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

// TestRenewViaNudgeAndIssue covers the renewal flow: RENEW_NUDGE{nonce} on the control stream → the client
// calls the mTLS POST /issue endpoint → the server regenerates the identity + public certs → the client
// swaps in the rotated identity (both certs change).
func TestRenewViaNudgeAndIssue(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control must bind before renewal")
	}
	originalID := string(c.Identity().IdentityCertPEM)

	if !ts.mgr.SendRenewNudge(testName, "00112233", "") {
		t.Fatal("SendRenewNudge should reach the live connection")
	}

	if !waitFor(t, 5*time.Second, func() bool {
		id := c.Identity()
		return string(id.IdentityCertPEM) != originalID && len(id.PublicCertPEM) > 0
	}) {
		t.Fatal("renewal must call /issue and swap in the regenerated identity + public certs")
	}
}
