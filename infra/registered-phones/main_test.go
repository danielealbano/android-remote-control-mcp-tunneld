package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
)

func TestCLI_EnrolledSinceFromTheEnvironment(t *testing.T) {
	t.Setenv("REGISTERED_PHONES_ENROLLED_SINCE", "2026-11-06")
	var c cli
	p, err := kong.New(&c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Parse([]string{"--s3-endpoint=http://127.0.0.1:1", "--s3-bucket=b", "--s3-access-key=k", "--s3-secret-key=s"}); err != nil {
		t.Fatal(err)
	}
	if c.EnrolledSince != "2026-11-06" || c.Textfile != "/var/lib/node_exporter/textfile_collector/arc_registered_phones.prom" {
		t.Fatalf("cli = %+v", c)
	}
}

func registryServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(code int, body string) {
			w.WriteHeader(code)
			if _, err := io.WriteString(w, body); err != nil {
				t.Errorf("write the S3 answer: %v", err)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/bucket" && r.URL.Query().Get("prefix") == "names/":
			write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>names/a</Key></Contents><Contents><Key>names/b</Key></Contents></ListBucketResult>`)
		case r.Method == http.MethodGet && r.URL.Path == "/bucket/names/a":
			write(http.StatusOK, `{"schema":1,"enrolled_at":"2026-11-07T10:00:00Z","ca":"letsencrypt","cert":{"serial":"01"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/bucket/names/b":
			write(http.StatusOK, `{"schema":1,"enrolled_at":"2026-11-07T11:00:00Z","ca":""}`)
		default:
			write(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExecute_CountsTheRegistry(t *testing.T) {
	t.Parallel()
	srv := registryServer(t)
	textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	c := cli{EnrolledSince: "2026-11-06", Textfile: textfile, S3Endpoint: srv.URL, S3Region: "us-east-1", S3Bucket: "bucket",
		S3AccessKey: "k", S3SecretKey: "s", S3ForcePathStyle: true}
	if code := execute(context.Background(), c, slog.New(slog.NewTextHandler(io.Discard, nil))); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got, err := os.ReadFile(textfile); err != nil || string(got) != metrics(1) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestExecute_AFailureLogsAndRemovesTheDashboardFile(t *testing.T) {
	t.Parallel()
	srv := registryServer(t)
	tests := []struct {
		name  string
		since string
		s3    string
		want  string
	}{
		{name: "a first day that is not a date", since: "2026-13-01", s3: srv.URL, want: `read the first counted day \"2026-13-01\"`},
		{name: "the bucket refuses", since: "2026-11-06", s3: srv.URL + "/denied", want: "list the name registry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
			if err := os.WriteFile(textfile, []byte(metrics(5)), 0o644); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			c := cli{EnrolledSince: tc.since, Textfile: textfile, S3Endpoint: tc.s3, S3Region: "us-east-1", S3Bucket: "bucket",
				S3AccessKey: "k", S3SecretKey: "s", S3ForcePathStyle: true}
			if code := execute(context.Background(), c, slog.New(slog.NewTextHandler(&logs, nil))); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if _, err := os.Stat(textfile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the old dashboard file must be removed, stat = %v", err)
			}
			if !strings.Contains(logs.String(), "could not count the registered phones") || !strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs = %s, want %q", logs.String(), tc.want)
			}
		})
	}
}
