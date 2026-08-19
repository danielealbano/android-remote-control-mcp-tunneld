package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
)

// errListener is a net.Listener whose Accept always fails with a fixed error (drives serveTLS's
// error-propagation branch without a real socket).
type errListener struct{ err error }

func (l errListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errListener) Close() error              { return nil }
func (l errListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// TestServeTLS_PropagatesNonShutdownError verifies serveTLS returns a non-shutdown Serve error (so the
// errgroup cancels), while ErrServerClosed / net.ErrClosed stay non-fatal.
func TestServeTLS_PropagatesNonShutdownError(t *testing.T) {
	boom := errors.New("permanent accept failure")
	if err := serveTLS(context.Background(), &http.Server{}, errListener{err: boom}, testLogger(), "x"); !errors.Is(err, boom) {
		t.Fatalf("a non-shutdown Serve error must propagate, got %v", err)
	}
	if err := serveTLS(context.Background(), &http.Server{}, errListener{err: net.ErrClosed}, testLogger(), "x"); err != nil {
		t.Fatalf("net.ErrClosed must be non-fatal, got %v", err)
	}
}

// TestServeInternal_DrainsGracefully verifies an in-flight request survives ctx cancellation: serveTLS
// closes the listener (stops accepting) but does NOT hard-Close the server, so the in-flight handler
// completes (the ordered drain's Shutdown is what bounds it).
func TestServeInternal_DrainsGracefully(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTLS(ctx, srv, ln, testLogger(), "internal") }()

	respCh := make(chan int, 1)
	go func() {
		resp, gerr := http.Get("http://" + ln.Addr().String() + "/")
		if gerr != nil {
			respCh <- -1
			return
		}
		respCh <- resp.StatusCode
		_ = resp.Body.Close()
	}()

	<-started
	cancel() // serveTLS closes the listener; the in-flight request MUST NOT be aborted
	close(release)
	select {
	case code := <-respCh:
		if code != http.StatusOK {
			t.Fatalf("in-flight request must complete gracefully, got %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
	if err := <-done; err != nil {
		t.Fatalf("serveTLS returned %v, want nil (net.ErrClosed is non-fatal)", err)
	}
}

// blockingRWC blocks Read forever until Close, and discards Write. It models the mesh request-body
// reader that never receives bytes from a quiet entry node.
type blockingRWC struct {
	ch   chan struct{}
	once sync.Once
}

func newBlockingRWC() *blockingRWC { return &blockingRWC{ch: make(chan struct{})} }
func (b *blockingRWC) Read(p []byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}
func (b *blockingRWC) Write(p []byte) (int, error) { return len(p), nil }
func (b *blockingRWC) Close() error {
	b.once.Do(func() { close(b.ch) })
	return nil
}

// eofThenBlockRWC returns EOF on the first Read (the phone terminating its side), then discards writes.
type eofThenBlockRWC struct {
	read  chan struct{}
	once  sync.Once
	rdone bool
}

func newEOFThenBlock() *eofThenBlockRWC { return &eofThenBlockRWC{read: make(chan struct{})} }
func (e *eofThenBlockRWC) Read(p []byte) (int, error) {
	if !e.rdone {
		e.rdone = true
		return 0, io.EOF // phone EOF immediately
	}
	<-e.read
	return 0, io.EOF
}
func (e *eofThenBlockRWC) Write(p []byte) (int, error) { return len(p), nil }
func (e *eofThenBlockRWC) Close() error {
	e.once.Do(func() { close(e.read) })
	return nil
}

// fakeOpener is a dial-back opener stub whose OpenStream always returns err (for the sentinel-translation test).
type fakeOpener struct{ err error }

func (f fakeOpener) OpenStream(context.Context, string, string) (phoneconn.DataStream, error) {
	return nil, f.err
}

// TestBridgeAdapter_TranslatesDuplicateStreamID covers the owner-side sentinel translation: a phone
// dial-back returning phoneconn.ErrDuplicateStreamID surfaces from OpenMesh as mesh.ErrDuplicateStream
// (so the mesh listener answers 422), while any other error passes through unchanged.
func TestBridgeAdapter_TranslatesDuplicateStreamID(t *testing.T) {
	b := &bridgeAdapter{mgr: fakeOpener{err: phoneconn.ErrDuplicateStreamID}, dialBackTimeout: time.Second}
	if _, err := b.OpenMesh(context.Background(), "t", "s1"); !errors.Is(err, mesh.ErrDuplicateStream) {
		t.Fatalf("OpenMesh must translate ErrDuplicateStreamID → mesh.ErrDuplicateStream, got %v", err)
	}

	other := errors.New("boom")
	b2 := &bridgeAdapter{mgr: fakeOpener{err: other}, dialBackTimeout: time.Second}
	if _, err := b2.OpenMesh(context.Background(), "t", "s1"); !errors.Is(err, other) {
		t.Fatalf("a non-duplicate error must pass through unchanged, got %v", err)
	}
}

// TestBridgeCopyReturnsPromptlyOnPhoneEOF proves that when the phone side (ds) EOFs while
// the mesh client read blocks forever, bridgeCopy must return promptly (via ds.Close/client.Close),
// NOT stall waiting for the client→phone copy to unblock.
func TestBridgeCopyReturnsPromptlyOnPhoneEOF(t *testing.T) {
	ds := newEOFThenBlock()    // phone: response direction EOFs at once
	client := newBlockingRWC() // entry: request-body read blocks forever
	done := make(chan struct{})
	go func() { bridgeCopy(ds, client); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bridgeCopy stalled on an abrupt phone close (must not wait for the entry idle timeout)")
	}
}
