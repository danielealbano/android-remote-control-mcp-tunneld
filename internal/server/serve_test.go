package server

import (
	"io"
	"sync"
	"testing"
	"time"
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
