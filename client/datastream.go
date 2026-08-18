package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// handleOpen answers a server OPEN by opening the matching dial-back data stream and splicing it to the
// backend. The data stream is opaque (no framing): the request body carries phone→client bytes, the
// response body carries client→phone bytes.
func (c *Client) handleOpen(ctx context.Context, payload []byte) {
	var op wire.OpenPayload
	if err := json.Unmarshal(payload, &op); err != nil || op.StreamID == "" {
		return
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.controlHost+"/data", pr)
	if err != nil {
		_ = pw.Close()
		return
	}
	req.Header.Set("X-Stream-Id", op.StreamID)
	resp, err := c.hc.Do(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		return
	}
	dc := &dataConn{r: resp.Body, w: pw, resp: resp}
	c.backend(dc)
	_ = dc.Close()
}

// dataConn is the phone side of one dial-back data stream: Read pulls client→phone bytes (the response
// body), Write pushes phone→client bytes (the request body). It is the io.ReadWriteCloser the backend
// splices to the phone's local target.
type dataConn struct {
	r    io.Reader
	w    *io.PipeWriter
	resp *http.Response
	once sync.Once
}

func (d *dataConn) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d *dataConn) Write(p []byte) (int, error) { return d.w.Write(p) }
func (d *dataConn) Close() error {
	d.once.Do(func() {
		_ = d.w.Close()
		_ = d.resp.Body.Close()
	})
	return nil
}
