// Package transport bridges public requests to the WS-holding node over Redis pub/sub. A frontend
// RoundTrips a request to req:{node} and awaits resp:{reqid}; the node's ServeNode loop invokes a
// handler and publishes the response.
package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
	"github.com/redis/go-redis/v9"
)

// ErrTimeout is the distinct sentinel a frontend maps to 504 + rec.Timeout() (never confused with a
// phone-origin 504 or an ErrCode-carried error).
var ErrTimeout = errors.New("transport: roundtrip timeout")

// RoundTrip subscribes to resp:{reqid} BEFORE publishing the request to req:{node} (so the response
// can never be missed), then returns the matching RespEnvelope. On timeout it returns
// (nil, ErrTimeout); a publish failure returns a different non-nil error. The subscription is closed
// on EVERY exit path (no pubsub leak).
func RoundTrip(ctx context.Context, rdb redis.UniversalClient, node string, req *wire.ReqEnvelope, timeout time.Duration) (*wire.RespEnvelope, error) {
	respChan := "resp:" + req.ReqID
	pubsub := rdb.Subscribe(ctx, respChan)
	defer func() { _ = pubsub.Close() }()

	// Confirm the subscription is active before publishing (subscribe-before-publish ordering).
	if _, err := pubsub.Receive(ctx); err != nil {
		return nil, err
	}
	if err := rdb.Publish(ctx, "req:"+node, wire.MarshalReq(req)).Err(); err != nil {
		return nil, err // publish failure → mapped to 502 + rec.PublishError() by the caller
	}

	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := pubsub.Channel()
	for {
		select {
		case <-deadline.Done():
			// reqCtx (ctx) is itself a WithTimeout of the same budget, so a genuine end-to-end timeout
			// surfaces here with ctx.Err() == DeadlineExceeded — that MUST still be ErrTimeout → 504.
			// Only a parent-context CANCEL (client gone) is reclassified.
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, context.Canceled
			}
			return nil, ErrTimeout
		case msg, ok := <-ch:
			if !ok {
				return nil, ErrTimeout
			}
			resp, err := wire.UnmarshalResp([]byte(msg.Payload))
			if err != nil || resp.ReqID != req.ReqID {
				continue // ignore malformed / foreign-reqid messages
			}
			return resp, nil
		}
	}
}

// ServeNode subscribes to req:{nodeID} and, per message, runs handle in its own goroutine (bounded
// by a WithTimeout(timeout) ctx so a phone that accepts but never completes a request still releases
// the goroutine) and publishes the response; a failed response-publish records rec.PublishError().
func ServeNode(ctx context.Context, rdb redis.UniversalClient, nodeID string, timeout time.Duration, rec observ.Recorder, log *slog.Logger, ready func(), handle func(context.Context, *wire.ReqEnvelope) *wire.RespEnvelope) error {
	pubsub := rdb.Subscribe(ctx, "req:"+nodeID)
	defer func() { _ = pubsub.Close() }()
	// Confirm the subscription is active before signalling readiness, so a request published to
	// req:{nodeID} in the startup window is never silently lost (fail startup if it cannot confirm).
	if _, err := pubsub.Receive(ctx); err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			payload := msg.Payload
			go serveOne(ctx, rdb, timeout, rec, log, handle, payload)
		}
	}
}

// serveOne handles one request message: decode, run handle under a per-message deadline, and publish
// the response. Split out so tests can drive it deterministically.
func serveOne(ctx context.Context, rdb redis.UniversalClient, timeout time.Duration, rec observ.Recorder, log *slog.Logger, handle func(context.Context, *wire.ReqEnvelope) *wire.RespEnvelope, payload string) {
	req, err := wire.UnmarshalReq([]byte(payload))
	if err != nil {
		log.Warn("dropping undecodable request envelope", "err", err)
		return
	}
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp := handle(hctx, req)
	if resp == nil {
		return
	}
	// Publish under the base ctx (NOT the per-message deadline) so a timed-out handle's synthetic
	// response is still delivered.
	if err := rdb.Publish(ctx, "resp:"+resp.ReqID, wire.MarshalResp(resp)).Err(); err != nil {
		rec.PublishError()
	}
}
