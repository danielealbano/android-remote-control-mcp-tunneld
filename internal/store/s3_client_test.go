package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestS3ClientSingleAttempt covers the plan's "s3 client single-attempt" row — the write-verify claim
// invariant: a failing PUT is NEVER silently replayed by SDK retries (a timed-out claim PUT replayed
// later would be a zombie write).
func TestS3ClientSingleAttempt(t *testing.T) {
	var puts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		// A retryable-by-default S3 error: with retries enabled the SDK would replay the PUT.
		http.Error(w, `<Error><Code>InternalError</Code></Error>`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	st, err := NewS3Store(context.Background(), S3Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "test",
		AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := st.PutName(ctx, "abc", NameRecord{Schema: 1}); err == nil {
		t.Fatal("a 500 PUT must surface an error")
	}
	if got := puts.Load(); got != 1 {
		t.Fatalf("the S3 client must attempt each request EXACTLY once (no retries), got %d PUTs", got)
	}
}
