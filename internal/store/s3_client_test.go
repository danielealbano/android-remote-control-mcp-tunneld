package store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

type closeFailBody struct{ io.Reader }

func (closeFailBody) Close() error { return errors.New("body close failed") }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestS3Store_GetName_ReturnsBodyCloseError(t *testing.T) {
	cli := s3.New(s3.Options{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		BaseEndpoint: aws.String("http://s3.example.test"), UsePathStyle: true,
		RetryMaxAttempts: 1, Retryer: aws.NopRetryer{},
		HTTPClient: doerFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: closeFailBody{strings.NewReader(`{"schema":1}`)}, Request: r,
			}, nil
		}),
	})
	st := &S3Store{cli: cli, bucket: "test"}
	rec, err := st.GetName(context.Background(), "abc")
	if err == nil || !strings.Contains(err.Error(), `store: close name "abc" body: body close failed`) {
		t.Fatalf("GetName = (%+v, %v), want the body close error", rec, err)
	}
}
