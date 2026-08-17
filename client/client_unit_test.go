package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_EnrollRejectsNonP256(t *testing.T) {
	c := New()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, _, err := c.Enroll(context.Background(), "http://unused.invalid/enroll", p384); err == nil {
		t.Error("a non-P-256 key must be rejected locally before any network call")
	}
}

func TestClient_EnrollErrors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if _, _, err := c.Enroll(context.Background(), srv.URL+"/enroll", key); err == nil {
		t.Error("a non-200 enroll response must surface an error")
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{not json")
	}))
	defer srv2.Close()
	if _, _, err := c.Enroll(context.Background(), srv2.URL+"/enroll", key); err == nil {
		t.Error("a malformed enroll JSON body must surface an error")
	}
}

func TestClient_ServeSurfacesConnectError(t *testing.T) {
	var got atomic.Int32
	c := &Client{OnConnectError: func(error) { got.Add(1) }}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	// An unreachable connect URL → each attempt fails → OnConnectError fires; ctx stops the loop.
	_ = c.Serve(ctx, "ws://127.0.0.1:1/connect", "abc.example.test", &x509.Certificate{}, key,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if got.Load() == 0 {
		t.Error("OnConnectError must be invoked on a failed connect attempt")
	}
}
