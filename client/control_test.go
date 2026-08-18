package client

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
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

// TestCertPushSwap covers CERT_PUSH updating the client's active identity.
func TestCertPushSwap(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})
	original := string(c.Identity().IdentityCertPEM)

	// A CERT_PUSH carrying a new cert for the same name must swap the active identity.
	newCertPEM := ts.ca.signLeaf(t, testName, &c.Identity().IdentityKey.PublicKey, false, nil)
	push, _ := json.Marshal(wire.CertPushPayload{IdentityCertPEM: string(newCertPEM), PublicCertPEM: string(newCertPEM)})
	c.installCerts(push)

	if got := string(c.Identity().IdentityCertPEM); got == original {
		t.Fatal("CERT_PUSH must swap the client's active identity cert")
	}
}

// TestRenewExchange covers RENEW_NUDGE → RENEW_REQUEST/CHALLENGE/SUBMIT → CERT_PUSH end to end.
func TestRenewExchange(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control must bind before renewal")
	}
	original := string(c.Identity().IdentityCertPEM)

	if !ts.mgr.SendRenewNudge(testName, "") {
		t.Fatal("SendRenewNudge should reach the live connection")
	}

	if !waitFor(t, 5*time.Second, func() bool {
		return string(c.Identity().IdentityCertPEM) != original && len(c.Identity().IdentityCertPEM) > 0
	}) {
		t.Fatal("renewal exchange must install the pushed cert (identity should change)")
	}
}
