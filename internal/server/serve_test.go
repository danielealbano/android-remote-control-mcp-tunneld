package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
)

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

// TestBridgeCopyReturnsPromptlyOnPhoneEOF is the W-001 regression: when the phone side (ds) EOFs while
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
