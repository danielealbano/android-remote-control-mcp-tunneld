package bucket_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
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
			write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>rejected-enroll/a.json</Key><LastModified>2026-11-06T10:00:00.000Z</LastModified></Contents></ListBucketResult>`)
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

func newTestBucket(t *testing.T) (*bucket.S3, *fakeS3) {
	t.Helper()
	f := &fakeS3{t: t, puts: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return bucket.New(bucket.Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	}), f
}

func TestS3_ListFollowsEveryPage(t *testing.T) {
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

func TestS3_ListObjectsCarriesTheLastWriteTime(t *testing.T) {
	t.Parallel()
	b, _ := newTestBucket(t)
	objs, err := b.ListObjects(context.Background(), "rejected-enroll/")
	if err != nil {
		t.Fatal(err)
	}
	want := []bucket.Object{
		{Key: "rejected-enroll/a.json", LastModified: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)},
		{Key: "rejected-enroll/b.json"},
	}
	if len(objs) != len(want) {
		t.Fatalf("objects = %v, want %v", objs, want)
	}
	for i := range want {
		if objs[i].Key != want[i].Key || !objs[i].LastModified.Equal(want[i].LastModified) {
			t.Fatalf("objects = %v, want %v", objs, want)
		}
	}
}

func TestS3_ListFailsWhenTheBucketRefuses(t *testing.T) {
	t.Parallel()
	b, _ := newTestBucket(t)
	if _, err := b.List(context.Background(), "names/"); err == nil || !strings.Contains(err.Error(), "list names/") {
		t.Fatalf("List = %v, want a list error", err)
	}
}

func TestS3_Get(t *testing.T) {
	t.Parallel()
	b, _ := newTestBucket(t)
	body, err := b.Get(context.Background(), "rejected-enroll/a.json")
	if err != nil || string(body) != `{"ts":"2026-11-06T10:00:00Z"}` {
		t.Fatalf("Get = %q, %v", body, err)
	}
	if _, err := b.Get(context.Background(), "refused-apps/attempts.json"); !errors.Is(err, bucket.ErrNotFound) {
		t.Fatalf("a missing object = %v, want ErrNotFound", err)
	}
}

func TestS3_Put(t *testing.T) {
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

func TestSettings_Config(t *testing.T) {
	t.Parallel()
	valid := bucket.Settings{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", Bucket: "b", AccessKey: "k", SecretKey: "s", ForcePathStyle: true}
	got, err := valid.Config()
	if err != nil || got != (bucket.Config{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", Bucket: "b", AccessKey: "k", SecretKey: "s", ForcePathStyle: true}) {
		t.Fatalf("Config = %+v, %v", got, err)
	}
	tests := []struct {
		name   string
		change func(*bucket.Settings)
		want   string
	}{
		{name: "no endpoint", change: func(s *bucket.Settings) { s.Endpoint = "" }, want: "the setting --s3-endpoint (TUNNELD_S3_ENDPOINT) is empty"},
		{name: "no bucket", change: func(s *bucket.Settings) { s.Bucket = "" }, want: "the setting --s3-bucket (TUNNELD_S3_BUCKET) is empty"},
		{name: "no access key", change: func(s *bucket.Settings) { s.AccessKey = "" }, want: "the setting --s3-access-key (TUNNELD_S3_ACCESS_KEY) is empty"},
		{name: "no secret key", change: func(s *bucket.Settings) { s.SecretKey = "" }, want: "the setting --s3-secret-key (TUNNELD_S3_SECRET_KEY) is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := valid
			tc.change(&s)
			if _, err := s.Config(); err == nil || err.Error() != tc.want {
				t.Fatalf("Config = %v, want %q", err, tc.want)
			}
		})
	}
}
