package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

var errInjected = errors.New("injected failure")

type failingBody struct{ io.Reader }

func (failingBody) Close() error { return errInjected }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newLoggedClient() (*Client, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Client{logger: slog.New(slog.NewTextHandler(&buf, nil))}, &buf
}

func TestDataConn_Close_ReturnsCloseErrorOnce(t *testing.T) {
	_, pw := io.Pipe()
	dc := &dataConn{r: strings.NewReader(""), w: pw, resp: &http.Response{Body: failingBody{strings.NewReader("")}}}
	if err := dc.Close(); !errors.Is(err, errInjected) {
		t.Fatalf("Close = %v, want the response-body close error", err)
	}
	if err := dc.Close(); err != nil {
		t.Fatalf("a repeated Close must be a no-op, got %v", err)
	}
}

func TestClient_HandleOpen_LogsBadPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "undecodable payload", payload: "{", want: `msg="malformed OPEN payload from the server (ignored)"`},
		{name: "missing stream id", payload: "{}", want: `msg="OPEN without a stream id from the server (ignored)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, buf := newLoggedClient()
			c.handleOpen(context.Background(), []byte(tc.payload))
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("the ignored OPEN must be logged; log = %q", buf.String())
			}
		})
	}
}

func TestClient_Renew_LogsFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "undecodable payload", payload: "{", want: `msg="malformed RENEW_NUDGE payload from the server (ignored)"`},
		{name: "missing nonce", payload: "{}", want: `msg="RENEW_NUDGE without a nonce from the server (ignored)"`},
		{name: "issuance fails", payload: `{"nonce":"00"}`, want: `msg="renew after a RENEW_NUDGE failed (keeping the current certs)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, buf := newLoggedClient()
			original := &Identity{Name: testName, CA: "test"}
			c.ident = original
			c.controlHost = testControlHost
			c.tunnelDomain = testTunnelDomain
			c.hc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errInjected
			})}
			c.renew(context.Background(), []byte(tc.payload))
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("the failed renewal must be logged; log = %q", buf.String())
			}
			if c.Identity() != original {
				t.Fatal("a failed renewal must keep the current identity")
			}
		})
	}
}
