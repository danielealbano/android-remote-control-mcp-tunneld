package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeS3 struct {
	t    *testing.T
	mu   sync.Mutex
	puts map[string]string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(code int, body string) {
		w.WriteHeader(code)
		if _, err := io.WriteString(w, body); err != nil {
			f.t.Errorf("write the S3 answer: %v", err)
		}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/bucket" && r.URL.Query().Get("list-type") == "2":
		if r.URL.Query().Get("prefix") != "rejected-enroll/" {
			write(http.StatusBadRequest, "<Error><Code>InvalidArgument</Code></Error>")
			return
		}
		if r.URL.Query().Get("continuation-token") == "" {
			write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>rejected-enroll/a.json</Key></Contents></ListBucketResult>`)
			return
		}
		write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>rejected-enroll/b.json</Key></Contents></ListBucketResult>`)
	case r.Method == http.MethodGet && r.URL.Path == "/bucket/rejected-enroll/a.json":
		write(http.StatusOK, `{"ts":"2026-11-06T10:00:00Z"}`)
	case r.Method == http.MethodGet:
		write(http.StatusNotFound, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
	case r.Method == http.MethodPut && r.URL.Path == "/bucket/refused-apps/attempts.json":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			write(http.StatusBadRequest, err.Error())
			return
		}
		f.mu.Lock()
		f.puts[r.URL.Path] = string(body)
		f.mu.Unlock()
		write(http.StatusOK, "")
	default:
		write(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
	}
}

func newTestBucket(t *testing.T) (*s3Bucket, *fakeS3) {
	t.Helper()
	f := &fakeS3{t: t, puts: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return newS3Bucket(bucketConfig{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	}), f
}

func TestS3Bucket_ListFollowsEveryPage(t *testing.T) {
	t.Parallel()
	b, _ := newTestBucket(t)
	keys, err := b.List(context.Background(), "rejected-enroll/")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "rejected-enroll/a.json,rejected-enroll/b.json" {
		t.Fatalf("keys = %v", keys)
	}
}

func TestS3Bucket_Get(t *testing.T) {
	t.Parallel()
	b, _ := newTestBucket(t)
	body, err := b.Get(context.Background(), "rejected-enroll/a.json")
	if err != nil || string(body) != `{"ts":"2026-11-06T10:00:00Z"}` {
		t.Fatalf("Get = %q, %v", body, err)
	}
	if _, err := b.Get(context.Background(), "refused-apps/attempts.json"); !errors.Is(err, errNotFound) {
		t.Fatalf("a missing object = %v, want errNotFound", err)
	}
}

func TestS3Bucket_Put(t *testing.T) {
	t.Parallel()
	b, f := newTestBucket(t)
	if err := b.Put(context.Background(), "refused-apps/attempts.json", []byte(`{"apps":{}}`)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.puts["/bucket/refused-apps/attempts.json"] != `{"apps":{}}` {
		t.Fatalf("puts = %v", f.puts)
	}
	if err := b.Put(context.Background(), "other.json", []byte("x")); err == nil {
		t.Fatal("a refused put must fail")
	}
}
