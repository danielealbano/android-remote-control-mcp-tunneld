package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseArgs_TheFirstDayFromTheEnvironmentAndTheDefaultTextfile(t *testing.T) {
	t.Setenv("REGISTERED_PHONES_ENROLLED_SINCE", "2026-11-06")
	var c cli
	if err := parseArgs(&c, []string{"--s3-endpoint=http://127.0.0.1:1", "--s3-bucket=b", "--s3-access-key=k", "--s3-secret-key=s"}); err != nil {
		t.Fatal(err)
	}
	if c.EnrolledSince != "2026-11-06" || c.Textfile != defaultTextfile {
		t.Fatalf("cli = %+v", c)
	}
	field, ok := reflect.TypeFor[cli]().FieldByName("Textfile")
	if !ok || field.Tag.Get("default") != defaultTextfile {
		t.Fatalf("the textfile flag default %q must equal defaultTextfile %q", field.Tag.Get("default"), defaultTextfile)
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
			write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated>`+
				`<Contents><Key>names/a</Key><LastModified>2026-11-07T10:00:01.000Z</LastModified></Contents>`+
				`<Contents><Key>names/b</Key><LastModified>2026-11-07T11:00:01.000Z</LastModified></Contents>`+
				`<Contents><Key>names/old</Key><LastModified>2026-10-15T10:00:00.000Z</LastModified></Contents></ListBucketResult>`)
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

func cliArgs(since, textfile, endpoint string, extra ...string) []string {
	return append([]string{"--enrolled-since=" + since, "--textfile=" + textfile, "--s3-endpoint=" + endpoint,
		"--s3-region=us-east-1", "--s3-bucket=bucket", "--s3-access-key=k", "--s3-secret-key=s"}, extra...)
}

func TestExecute_CountsTheRegistry(t *testing.T) {
	t.Parallel()
	srv := registryServer(t)
	textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	var logs bytes.Buffer
	code := execute(context.Background(), cliArgs("2026-11-06", textfile, srv.URL), capturedLog(&logs), withClock(func() time.Time { return testNow }))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; logs %s", code, logs.String())
	}
	if got, err := os.ReadFile(textfile); err != nil || string(got) != metrics(1, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
	if !strings.Contains(logs.String(), "registered=1 names_listed=3 names_read=2") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestExecute_AFailureLogsAndRemovesTheDashboardFile(t *testing.T) {
	t.Parallel()
	srv := registryServer(t)
	tests := []struct {
		name string
		args func(textfile string) []string
		want string
	}{
		{name: "a first day that is not a date", args: func(tf string) []string { return cliArgs("2026-13-01", tf, srv.URL) },
			want: `read the first counted day \"2026-13-01\"`},
		{name: "the bucket refuses", args: func(tf string) []string { return cliArgs("2026-11-06", tf, srv.URL+"/denied") },
			want: "list the name registry"},
		{name: "a required setting is missing", args: func(tf string) []string {
			return []string{"--enrolled-since=2026-11-06", "--textfile=" + tf, "--s3-endpoint=" + srv.URL, "--s3-access-key=k", "--s3-secret-key=s"}
		}, want: "read the settings: missing flags: --s3-bucket"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
			if err := os.WriteFile(textfile, []byte(metrics(5, testNow)), 0o644); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			if code := execute(context.Background(), tc.args(textfile), capturedLog(&logs)); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if _, err := os.Stat(textfile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the old dashboard file must be removed, stat = %v; logs %s", err, logs.String())
			}
			if !strings.Contains(logs.String(), "could not count the registered phones, so this node's dashboard file was removed") ||
				!strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs = %s, want %q", logs.String(), tc.want)
			}
		})
	}
}

func TestExecute_AnInvalidSettingFromTheEnvironmentRemovesTheDashboardFile(t *testing.T) {
	textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	if err := os.WriteFile(textfile, []byte(metrics(5, testNow)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTERED_PHONES_TEXTFILE", textfile)
	t.Setenv("TUNNELD_S3_FORCE_PATH_STYLE", "maybe")
	var logs bytes.Buffer
	args := []string{"--enrolled-since=2026-11-06", "--s3-endpoint=http://127.0.0.1:1", "--s3-bucket=b", "--s3-access-key=k", "--s3-secret-key=s"}
	if code := execute(context.Background(), args, capturedLog(&logs)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if _, err := os.Stat(textfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the old dashboard file must be removed, stat = %v; logs %s", err, logs.String())
	}
}

func TestExecute_AnUnreadableCommandLineCountsNothingAndRemovesNothing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		extra string
		want  string
	}{
		{name: "an unknown flag", extra: "--colour", want: "unknown flag --colour"},
		{name: "a flag with an invalid value", extra: "--s3-force-path-style=maybe", want: "--s3-force-path-style"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
			if err := os.WriteFile(textfile, []byte(metrics(5, testNow)), 0o644); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			if code := execute(context.Background(), cliArgs("2026-11-06", textfile, "http://127.0.0.1:1", tc.extra), capturedLog(&logs)); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if !strings.Contains(logs.String(), "could not read the command line, so nothing was counted and no dashboard file was removed") ||
				!strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs = %s, want %q", logs.String(), tc.want)
			}
			if got, err := os.ReadFile(textfile); err != nil || string(got) != metrics(5, testNow) {
				t.Fatalf("a run that read no settings must leave the file alone: %q, %v", got, err)
			}
		})
	}
}

func TestExecute_AnUnremovableDashboardFileIsLoggedAsKept(t *testing.T) {
	t.Parallel()
	textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	if err := os.MkdirAll(filepath.Join(textfile, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if code := execute(context.Background(), cliArgs("2026-13-01", textfile, "http://127.0.0.1:1"), capturedLog(&logs)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(logs.String(), "this node's dashboard file could not be removed, so the dashboard keeps its old count until that count is two hours old") {
		t.Fatalf("logs = %s", logs.String())
	}
}
