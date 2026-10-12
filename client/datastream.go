package client

import (
	"context"
	"encoding/json"
	"errors"
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
	if err := json.Unmarshal(payload, &op); err != nil {
		c.logger.Warn("malformed OPEN payload from the server (ignored)", "err", err)
		return
	}
	if op.StreamID == "" {
		c.logger.Warn("OPEN without a stream id from the server (ignored)")
		return
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.controlHost+"/api/v1/data", pr)
	if err != nil {
		c.logger.Warn("data stream request build failed", "stream", op.StreamID, "err", err)
		c.closeLogged("data request body", pw)
		return
	}
	req.Header.Set("X-Stream-Id", op.StreamID)
	resp, err := c.hc.Do(req)
	if err != nil {
		c.logger.Debug("data stream dial-back failed", "stream", op.StreamID, "err", err)
		pw.CloseWithError(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("data stream dial-back refused", "stream", op.StreamID, "status", resp.StatusCode)
		c.closeLogged("data response body", resp.Body)
		c.closeLogged("data request body", pw)
		return
	}
	dc := &dataConn{r: resp.Body, w: pw, resp: resp}
	c.backend(dc)
	c.closeLogged("data stream", dc)
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
	var err error
	d.once.Do(func() {
		err = errors.Join(d.w.Close(), d.resp.Body.Close())
	})
	return err
}
