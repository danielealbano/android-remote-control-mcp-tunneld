package main

import (
	"context"
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

func envNames(typ reflect.Type) []string {
	var out []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if _, ok := f.Tag.Lookup("embed"); ok && f.Type.Kind() == reflect.Struct {
			out = append(out, envNames(f.Type)...)
			continue
		}
		for _, k := range strings.Split(f.Tag.Get("env"), ",") {
			if k != "" {
				out = append(out, k)
			}
		}
	}
	return out
}

func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range envNames(reflect.TypeFor[cli]()) {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseArgs_DefaultsAndTheBucketSettings(t *testing.T) {
	isolateEnv(t)
	t.Setenv("TUNNELD_S3_BUCKET", "b")
	var c cli
	if err := parseArgs(&c, []string{"--s3-endpoint=http://127.0.0.1:1", "--s3-access-key=k", "--s3-secret-key=s"}); err != nil {
		t.Fatal(err)
	}
	if c.Textfile != defaultTextfile || c.CacheFile != defaultCacheFile || c.S3.Bucket != "b" {
		t.Fatalf("cli = %+v", c)
	}
	for field, want := range map[string]string{"Textfile": defaultTextfile, "CacheFile": defaultCacheFile} {
		f, ok := reflect.TypeFor[cli]().FieldByName(field)
		if !ok || f.Tag.Get("default") != want {
			t.Fatalf("the %s flag default %q must equal %q", field, f.Tag.Get("default"), want)
		}
	}
}

func listServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(code int, body string) {
			w.WriteHeader(code)
			if _, err := io.WriteString(w, body); err != nil {
				t.Errorf("write the S3 answer: %v", err)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/bucket" && r.URL.Query().Get("prefix") == "phones-seen/":
			write(http.StatusOK, `<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated>`+
				`<Contents><Key>phones-seen/2026/11/26/0a1b.json</Key><ETag>&quot;e1&quot;</ETag></Contents></ListBucketResult>`)
		case r.Method == http.MethodGet && r.URL.Path == "/bucket/phones-seen/2026/11/26/0a1b.json":
			write(http.StatusOK, `{"schema":1,"node":"0a1b","day":"2026-11-26","phones":{"abc":{"first":"2026-11-26T09:00:00Z","last":"2026-11-26T11:00:00Z"}}}`)
		default:
			write(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cliArgs(textfile, endpoint string, extra ...string) []string {
	return append([]string{"--textfile=" + textfile, "--cache-file=" + filepath.Join(filepath.Dir(textfile), "cache.json"),
		"--s3-endpoint=" + endpoint, "--s3-region=us-east-1", "--s3-bucket=bucket", "--s3-access-key=k", "--s3-secret-key=s"}, extra...)
}

func TestExecute_CountsTheListsInTheBucket(t *testing.T) {
	isolateEnv(t)
	srv := listServer(t)
	textfile := filepath.Join(t.TempDir(), "arc_active_users.prom")
	logs := &syncBuf{}
	code := execute(context.Background(), cliArgs(textfile, srv.URL), capturedLog(logs), withClock(func() time.Time { return testNow }))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; logs %s", code, logs.String())
	}
	if got, err := os.ReadFile(textfile); err != nil || string(got) != wantCounts(1, 1, 1) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(textfile), "cache.json")); err != nil {
		t.Fatalf("the run must save its cache: %v", err)
	}
}

func TestExecute_AFailureLogsAndLeavesTheDashboardFileAsItWas(t *testing.T) {
	isolateEnv(t)
	srv := listServer(t)
	tests := []struct {
		name string
		args func(textfile string) []string
		env  map[string]string
		want string
	}{
		{name: "the bucket refuses", args: func(tf string) []string { return cliArgs(tf, srv.URL+"/denied") }, want: "list the lists of phones seen"},
		{name: "a required setting is missing", args: func(tf string) []string {
			return []string{"--textfile=" + tf, "--s3-endpoint=" + srv.URL, "--s3-access-key=k", "--s3-secret-key=s"}
		}, want: "read the settings: missing flags: --s3-bucket"},
		{name: "an unknown flag", args: func(tf string) []string { return cliArgs(tf, srv.URL, "--colour") }, want: "read the settings: unknown flag --colour"},
		{name: "an empty cache file path", args: func(tf string) []string { return cliArgs(tf, srv.URL, "--cache-file=") }, want: "the cache file path is empty"},
		{name: "an empty secret key from the environment", args: func(tf string) []string {
			return []string{"--textfile=" + tf, "--s3-endpoint=" + srv.URL, "--s3-bucket=bucket", "--s3-access-key=k"}
		}, env: map[string]string{"TUNNELD_S3_SECRET_KEY": ""}, want: "the setting --s3-secret-key (TUNNELD_S3_SECRET_KEY) is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			textfile := filepath.Join(t.TempDir(), "arc_active_users.prom")
			before := wantCounts(5, 6, 7)
			if err := os.WriteFile(textfile, []byte(before), 0o644); err != nil {
				t.Fatal(err)
			}
			logs := &syncBuf{}
			if code := execute(context.Background(), tc.args(textfile), capturedLog(logs)); code != 1 {
				t.Fatalf("exit code = %d, want 1; logs %s", code, logs.String())
			}
			if !strings.Contains(logs.String(), "the active-users count failed, so this node's dashboard file was not updated; the dashboard ignores counts more than an hour old") ||
				!strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs = %s, want %q", logs.String(), tc.want)
			}
			if got, err := os.ReadFile(textfile); err != nil || string(got) != before {
				t.Fatalf("a failed run must leave the dashboard file as it was: %q, %v", got, err)
			}
		})
	}
}
