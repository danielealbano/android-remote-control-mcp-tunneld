package phoneconn

import (
	"encoding/binary"
	"io"
	"sync"
)

// httpDataStream splices one dial-back data stream: Read pulls phone→client bytes from the /data
// request body; Write pushes client→phone bytes to the /data response body (flushed). Close signals the
// serveData handler to return. Write and Close share a mutex + closed flag so that once Close signals the
// handler to return, NO further Write touches the HTTP/2 response writer — the http2 library finalizes
// the response writer as the handler returns, and writing it concurrently is a data race.
type httpDataStream struct {
	r     io.Reader
	w     io.Writer
	flush func()
	done  chan struct{}
	once  sync.Once

	mu     sync.Mutex
	closed bool
}

func (d *httpDataStream) Read(p []byte) (int, error) { return d.r.Read(p) }

func (d *httpDataStream) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := d.w.Write(p)
	if d.flush != nil {
		d.flush()
	}
	return n, err
}

func (d *httpDataStream) Close() error {
	d.once.Do(func() {
		// Wait for any in-flight Write to finish and block future ones BEFORE releasing the handler: after
		// close(done) the handler returns and the http2 library touches the response writer.
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		close(d.done)
	})
	return nil
}

// readControlFrame reads one length-framed v2 control frame from r: [type:1][len:4 BE][payload].
func readControlFrame(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	frame := make([]byte, 5+int(n))
	copy(frame, hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return nil, err
	}
	return frame, nil
}
