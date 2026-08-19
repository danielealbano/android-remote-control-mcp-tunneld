package phoneconn

import (
	"sync"
	"testing"
	"time"
)

// blockingWriter blocks every Write (holding httpDataStream.mu) until release is closed, and signals
// via entered once the first Write is in progress — so a test can guarantee Close races a Write that
// already holds the mutex.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

// TestHTTPDataStream_CloseUnblocksBlockedWrite proves that a Write blocked inside the response writer
// (holding d.mu) must be released by Close via the unblock hook, so Close does not deadlock on the mutex.
func TestHTTPDataStream_CloseUnblocksBlockedWrite(t *testing.T) {
	bw := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	ds := &httpDataStream{
		w:       bw,
		done:    make(chan struct{}),
		unblock: func() { close(bw.release) }, // reset: releases the blocked Write
	}

	writeReturned := make(chan struct{})
	go func() {
		_, _ = ds.Write([]byte("hello"))
		close(writeReturned)
	}()
	<-bw.entered // the Write now holds d.mu, blocked in the writer

	closeReturned := make(chan struct{})
	go func() {
		_ = ds.Close()
		close(closeReturned)
	}()

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked: unblock did not release the mutex-holding Write")
	}
	select {
	case <-writeReturned:
	case <-time.After(time.Second):
		t.Fatal("the blocked Write was not released by unblock")
	}
	select {
	case <-ds.done:
	default:
		t.Fatal("Close must signal done")
	}
}
