package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

func TestEnvNames_IncludesTheEmbeddedBucketSettings(t *testing.T) {
	t.Parallel()
	got := strings.Join(envNames(reflect.TypeFor[cli]()), ",")
	for _, want := range []string{"REGISTERED_PHONES_ENROLLED_SINCE", "REGISTERED_PHONES_STATE_FILE", "TUNNELD_S3_BUCKET", "TUNNELD_S3_FORCE_PATH_STYLE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("env names = %s, want %s among them", got, want)
		}
	}
}

func TestParseArgs_TheFirstDayFromTheEnvironmentAndTheDefaultTextfile(t *testing.T) {
	isolateEnv(t)
	t.Setenv("REGISTERED_PHONES_ENROLLED_SINCE", "2026-11-06")
	var c cli
	if err := parseArgs(&c, []string{"--s3-endpoint=http://127.0.0.1:1", "--s3-bucket=b", "--s3-access-key=k", "--s3-secret-key=s"}); err != nil {
		t.Fatal(err)
	}
	if c.EnrolledSince != "2026-11-06" || c.Textfile != defaultTextfile || c.StateFile != defaultStateFile {
		t.Fatalf("cli = %+v", c)
	}
	for field, want := range map[string]string{"Textfile": defaultTextfile, "StateFile": defaultStateFile} {
		f, ok := reflect.TypeFor[cli]().FieldByName(field)
		if !ok || f.Tag.Get("default") != want {
			t.Fatalf("the %s flag default %q must equal %q", field, f.Tag.Get("default"), want)
		}
	}
}

type registry struct {
	mu    sync.Mutex
	state []byte
}

func (g *registry) savedState() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

func registryServer(t *testing.T) (*httptest.Server, *registry) {
	t.Helper()
	g := &registry{}
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
		case r.Method == http.MethodGet && r.URL.Path == "/bucket/registered-phones/state.json":
			write(http.StatusNotFound, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
		case r.Method == http.MethodPut && r.URL.Path == "/bucket/registered-phones/state.json":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				write(http.StatusBadRequest, err.Error())
				return
			}
			g.mu.Lock()
			g.state = body
			g.mu.Unlock()
			write(http.StatusOK, "")
		default:
			write(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, g
}

func cliArgs(since, textfile, endpoint string, extra ...string) []string {
	return append([]string{"--enrolled-since=" + since, "--textfile=" + textfile,
		"--state-file=" + filepath.Join(filepath.Dir(textfile), "state.json"), "--s3-endpoint=" + endpoint,
		"--s3-region=us-east-1", "--s3-bucket=bucket", "--s3-access-key=k", "--s3-secret-key=s"}, extra...)
}

func TestExecute_CountsTheRegistry(t *testing.T) {
	isolateEnv(t)
	srv, reg := registryServer(t)
	textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	var logs bytes.Buffer
	code := execute(context.Background(), cliArgs("2026-11-06", textfile, srv.URL), capturedLog(&logs), withClock(func() time.Time { return testNow }))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; logs %s", code, logs.String())
	}
	if got, err := os.ReadFile(textfile); err != nil || string(got) != metrics(1, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
	if !strings.Contains(logs.String(), "registered=1 new=1 names_listed=3 names_read=2") {
		t.Fatalf("logs = %s", logs.String())
	}
	saved, err := decodeState(reg.savedState(), "saved in the test bucket")
	if err != nil || names(saved) != "a" {
		t.Fatalf("saved state = %+v, %v", saved, err)
	}
	if node, err := os.ReadFile(filepath.Join(filepath.Dir(textfile), "state.json")); err != nil || !bytes.Equal(node, reg.savedState()) {
		t.Fatalf("the node copy must match the bucket copy: %q, %v", node, err)
	}
}

func TestExecute_AFailureLogsAndLeavesTheDashboardFileAsItWas(t *testing.T) {
	isolateEnv(t)
	srv, _ := registryServer(t)
	tests := []struct {
		name string
		args func(textfile string) []string
		want string
	}{
		{name: "a first day that is not a date", args: func(tf string) []string { return cliArgs("2026-13-01", tf, srv.URL) },
			want: `read the first counted day \"2026-13-01\"`},
		{name: "the bucket refuses", args: func(tf string) []string { return cliArgs("2026-11-06", tf, srv.URL+"/denied") },
			want: "read the state from the bucket"},
		{name: "a required setting is missing", args: func(tf string) []string {
			return []string{"--enrolled-since=2026-11-06", "--textfile=" + tf, "--s3-endpoint=" + srv.URL, "--s3-access-key=k", "--s3-secret-key=s"}
		}, want: "read the settings: missing flags: --s3-bucket"},
		{name: "an unknown flag", args: func(tf string) []string { return cliArgs("2026-11-06", tf, srv.URL, "--colour") },
			want: "read the settings: unknown flag --colour"},
		{name: "a flag with an invalid value", args: func(tf string) []string { return cliArgs("2026-11-06", tf, srv.URL, "--s3-force-path-style=maybe") },
			want: "read the settings: --s3-force-path-style"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
			assertFailureKeepsTheFile(t, textfile, func(logger *slog.Logger) int { return execute(context.Background(), tc.args(textfile), logger) }, tc.want)
		})
	}
}

func TestExecute_ABadSettingFromTheEnvironmentLeavesTheDashboardFileAsItWas(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "an invalid value", env: map[string]string{"TUNNELD_S3_FORCE_PATH_STYLE": "maybe"}, want: "TUNNELD_S3_FORCE_PATH_STYLE"},
		{name: "an empty dashboard file path", env: map[string]string{"REGISTERED_PHONES_TEXTFILE": ""}, want: "the dashboard file path is empty"},
		{name: "an empty state file path", env: map[string]string{"REGISTERED_PHONES_STATE_FILE": ""}, want: "the state file path is empty"},
		{name: "an empty endpoint", env: map[string]string{"TUNNELD_S3_ENDPOINT": ""}, want: "the setting --s3-endpoint (TUNNELD_S3_ENDPOINT) is empty"},
		{name: "an empty bucket", env: map[string]string{"TUNNELD_S3_BUCKET": ""}, want: "the setting --s3-bucket (TUNNELD_S3_BUCKET) is empty"},
		{name: "an empty access key", env: map[string]string{"TUNNELD_S3_ACCESS_KEY": ""}, want: "the setting --s3-access-key (TUNNELD_S3_ACCESS_KEY) is empty"},
		{name: "an empty secret key", env: map[string]string{"TUNNELD_S3_SECRET_KEY": ""}, want: "the setting --s3-secret-key (TUNNELD_S3_SECRET_KEY) is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			textfile := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
			env := map[string]string{
				"REGISTERED_PHONES_ENROLLED_SINCE": "2026-11-06", "REGISTERED_PHONES_TEXTFILE": textfile,
				"REGISTERED_PHONES_STATE_FILE": filepath.Join(filepath.Dir(textfile), "state.json"),
				"TUNNELD_S3_ENDPOINT":          "http://127.0.0.1:1", "TUNNELD_S3_BUCKET": "b", "TUNNELD_S3_ACCESS_KEY": "k", "TUNNELD_S3_SECRET_KEY": "s",
			}
			for k, v := range tc.env {
				env[k] = v
			}
			for k, v := range env {
				t.Setenv(k, v)
			}
			assertFailureKeepsTheFile(t, textfile, func(logger *slog.Logger) int { return execute(context.Background(), nil, logger) }, tc.want)
		})
	}
}

func assertFailureKeepsTheFile(t *testing.T, textfile string, run func(*slog.Logger) int, want string) {
	t.Helper()
	if err := os.WriteFile(textfile, []byte(metrics(5, testNow)), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if code := run(capturedLog(&logs)); code != 1 {
		t.Fatalf("exit code = %d, want 1; logs %s", code, logs.String())
	}
	if !strings.Contains(logs.String(), "the registered-phones count failed, so this node's dashboard file was not updated; the dashboard ignores counts more than two hours old") ||
		!strings.Contains(logs.String(), want) {
		t.Fatalf("logs = %s, want %q", logs.String(), want)
	}
	if got, err := os.ReadFile(textfile); err != nil || string(got) != metrics(5, testNow) {
		t.Fatalf("a failed run must leave the dashboard file as it was: %q, %v", got, err)
	}
}
