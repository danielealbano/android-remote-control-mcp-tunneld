package wsconn

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Conn is one authenticated phone WebSocket. Up to --limit-concurrent Do goroutines multiplex over
// it; a single read-pump owns all reads and response reassembly.
type Conn struct {
	name, fp, connID string
	ws               *websocket.Conn
	mgr              *Manager
	up, down         *limit.TokenBucket
	writeMu          sync.Mutex
	pending          sync.Map // reqid -> *inflight
	ctx              context.Context
	cancel           context.CancelFunc
	closeOnce        sync.Once
}

// inflight tracks one in-flight request's response reassembly. ch is buffered 1.
type inflight struct {
	ch   chan *wire.RespEnvelope
	head *wire.RespEnvelope
	body bytes.Buffer
}

// serve runs the read-pump plus heartbeat/keepalive until the WS closes, then tears down.
func (c *Conn) serve() {
	go c.runHeartbeat()
	go c.runKeepalive()
	reason := c.readPump()
	c.teardown(reason)
}

// Do sends REQUEST_HEAD (unpaced) + paced REQUEST_BODY_CHUNKs + REQUEST_END and awaits the assembled
// response. writeMu is released between frames so pings and other Do frames interleave.
func (c *Conn) Do(ctx context.Context, req *wire.ReqEnvelope) *wire.RespEnvelope {
	inf := &inflight{ch: make(chan *wire.RespEnvelope, 1)}
	c.pending.Store(req.ReqID, inf)
	defer c.pending.Delete(req.ReqID)

	if err := c.write(ctx, wire.REQUEST_HEAD, wire.EncodeReqHeader(req), nil); err != nil {
		return c.sendFailure(ctx, req.ReqID)
	}
	// Double-pacing guard: if this node's up-bucket already paced the ingress body read
	// (docs/ARCHITECTURE.md §4), skip the token drain here (byte accounting is still recorded for
	// every chunk written).
	skipPace := req.PacedByNode == c.mgr.nodeID
	for _, chunk := range chunkBytes(req.Body, wire.ChunkSize) {
		if !skipPace {
			if err := c.up.WaitN(ctx, len(chunk)); err != nil {
				return c.sendFailure(ctx, req.ReqID)
			}
		}
		if err := c.write(ctx, wire.REQUEST_BODY_CHUNK, wire.EncodeReqIDHeader(req.ReqID), chunk); err != nil {
			return c.sendFailure(ctx, req.ReqID)
		}
		// Record AFTER a successful write (mirrors the read-pump's record-after-receipt): a chunk that
		// failed to reach the wire must not inflate bytes_out.
		c.mgr.rec.Bytes(c.name, "out", int64(len(chunk)))
	}
	if err := c.write(ctx, wire.REQUEST_END, wire.EncodeReqIDHeader(req.ReqID), nil); err != nil {
		return c.sendFailure(ctx, req.ReqID)
	}

	select {
	case resp := <-inf.ch:
		return resp
	case <-ctx.Done():
		return nil // per-message deadline reached; the frontend times out → 504 (no publish)
	case <-c.ctx.Done():
		return synthErr(req.ReqID, "tunnel_gone")
	}
}

// sendFailure maps a send-leg error to the response the frontend should see: a per-message ctx
// deadline/cancel is a timeout (nil → 504, matching the post-END select arm), any other write failure
// is a dead tunnel (502).
func (c *Conn) sendFailure(ctx context.Context, reqid string) *wire.RespEnvelope {
	if ctx.Err() != nil {
		return nil // deadline/cancel → frontend maps to 504
	}
	return synthErr(reqid, "tunnel_gone")
}

// readPump owns all WS reads and response reassembly, routing each RESPONSE_*/ERROR frame to the
// matching inflight by reqid. Returns the disconnect reason.
func (c *Conn) readPump() string {
	for {
		_, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return closeReasonFromErr(err)
		}
		typ, hdr, body, derr := wire.DecodeFrame(data)
		if derr != nil {
			continue
		}
		switch typ {
		case wire.RESPONSE_HEAD:
			rid, code, h := wire.DecodeRespHeader(hdr)
			// The phone is authenticated but its response CONTENT is untrusted: an out-of-range status
			// (0 from an omitted field, or > 599) would panic the frontend's http.WriteHeader and
			// poison the {code} metric label. Clamp a malformed status to 502 at this trust boundary.
			if code < 100 || code > 599 {
				code = http.StatusBadGateway
			}
			if inf := c.get(rid); inf != nil {
				inf.head = &wire.RespEnvelope{ReqID: rid, Status: code, Header: h}
			}
		case wire.RESPONSE_BODY_CHUNK:
			rid := wire.FrameReqID(hdr)
			// Pace + account EVERY response chunk before dispatch/drop, so the per-tunnel bandwidth cap
			// and byte accounting hold even while draining bytes the client will never receive (an
			// over-cap or aborted response) — docs/ARCHITECTURE.md §4.
			if err := c.down.WaitN(c.ctx, len(body)); err != nil {
				if errors.Is(err, limit.ErrBurstExceeded) {
					c.mgr.log.Warn("oversized response chunk exceeds bandwidth burst; tearing down", "tunnel", c.name, "bytes", len(body))
					return "oversized_frame"
				}
				return "shutdown"
			}
			c.mgr.rec.Bytes(c.name, "in", int64(len(body)))
			inf := c.get(rid)
			if inf == nil {
				continue // unknown/aborted/over-cap reqid: bytes already paced+accounted; drop the payload
			}
			if int64(inf.body.Len())+int64(len(body)) > c.mgr.responseLimit {
				c.mgr.rec.Reject("response_too_large", c.name, "")
				c.resolve(rid, &wire.RespEnvelope{ReqID: rid, Status: http.StatusBadGateway, Err: "response too large", ErrCode: "response_too_large"})
				continue
			}
			inf.body.Write(body)
		case wire.RESPONSE_END:
			rid := wire.FrameReqID(hdr)
			if inf := c.get(rid); inf != nil {
				resp := inf.head
				if resp == nil {
					resp = &wire.RespEnvelope{ReqID: rid, Status: http.StatusBadGateway, Err: "missing response head", ErrCode: "phone_error"}
				}
				resp.Body = append([]byte(nil), inf.body.Bytes()...)
				c.resolve(rid, resp)
			}
		case wire.ERROR:
			rid, msg := wire.DecodeErrorHeader(hdr)
			c.resolve(rid, &wire.RespEnvelope{ReqID: rid, Status: http.StatusBadGateway, Err: msg, ErrCode: "phone_error"})
		default:
			// CHALLENGE/AUTH never arrive post-handshake; ignore.
		}
	}
}

func (c *Conn) write(ctx context.Context, t wire.FrameType, header, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.Write(ctx, websocket.MessageBinary, wire.EncodeFrame(t, header, body))
}

func (c *Conn) get(reqid string) *inflight {
	if v, ok := c.pending.Load(reqid); ok {
		return v.(*inflight)
	}
	return nil
}

func (c *Conn) resolve(reqid string, resp *wire.RespEnvelope) {
	if v, ok := c.pending.LoadAndDelete(reqid); ok {
		select {
		case v.(*inflight).ch <- resp:
		default:
		}
	}
}

// teardown closes the WS, removes the Conn/route (conn-identity-conditional), cancels the conn ctx,
// fails all pending with a 502, and records the disconnect — exactly once.
func (c *Conn) teardown(reason string) {
	c.closeOnce.Do(func() {
		c.mgr.conns.CompareAndDelete(c.name, c)
		uctx, ucancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.mgr.registry.Unbind(uctx, c.name, c.connID); err != nil {
			c.mgr.log.Warn("route unbind on teardown failed", "tunnel", c.name, "err", err)
		}
		ucancel()
		c.cancel()
		c.mgr.buckets.Unpin(c.name)
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
		c.pending.Range(func(k, v any) bool {
			c.pending.Delete(k)
			select {
			case v.(*inflight).ch <- synthErr(k.(string), "tunnel_gone"):
			default:
			}
			return true
		})
		c.mgr.rec.WSDisconnect(reason)
	})
}

func closeReasonFromErr(err error) string {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return "client_close"
	default:
		return "dead_peer"
	}
}
