package main

import (
	"context"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram/telegramtest"
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

func requiredArgs(overrides ...string) []string {
	args := map[string]string{
		"--node": "n2", "--timezone": "UTC", "--daily-hour": "9", "--telegram-token": testBotToken, "--telegram-chat": "42",
		"--s3-endpoint": "http://127.0.0.1:1", "--s3-bucket": "b", "--s3-access-key": "k", "--s3-secret-key": "s",
	}
	for i := 0; i+1 < len(overrides); i += 2 {
		if overrides[i+1] == "" && overrides[i] != "--s3-bucket" {
			delete(args, overrides[i])
			continue
		}
		args[overrides[i]] = overrides[i+1]
	}
	var out []string
	for k, v := range args {
		out = append(out, k+"="+v)
	}
	return out
}

func telegramServer(t *testing.T) (*telegramtest.Server, string) {
	t.Helper()
	srv := &telegramtest.Server{T: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, ts.URL
}

func TestEnvNames_IncludesTheEmbeddedBucketSettings(t *testing.T) {
	t.Parallel()
	got := strings.Join(envNames(reflect.TypeFor[cli]()), ",")
	for _, want := range []string{"BUSY_CLIENTS_NODE", "BUSY_CLIENTS_DAILY_HOUR", "BUSY_CLIENTS_EXCLUDE", "TUNNELD_S3_BUCKET"} {
		if !strings.Contains(got, want) {
			t.Fatalf("env names = %s, want %s among them", got, want)
		}
	}
}

func TestParseArgs_Defaults(t *testing.T) {
	isolateEnv(t)
	var c cli
	if err := parseArgs(&c, requiredArgs()); err != nil {
		t.Fatal(err)
	}
	wantOpenAI := []string{"https://openai.com/chatgpt-connectors.json", "https://openai.com/chatgpt-actions.json", "https://openai.com/chatgpt-user.json"}
	if c.Connections != 500 || c.SpreadConnections != 100 || c.SpreadTunnels != 3 || c.DailyHour != 9 ||
		!reflect.DeepEqual(c.OpenAIRanges, wantOpenAI) || c.AnthropicRanges != "https://platform.claude.com/docs/en/api/ip-addresses" || c.Exclude != nil {
		t.Fatalf("cli = %+v", c)
	}
}

func TestParseArgs_ExcludeFromTheEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{name: "an empty setting excludes nothing", env: "", want: nil},
		{name: "a comma separates the entries", env: "198.51.100.7,203.0.113.0/24", want: []string{"198.51.100.7", "203.0.113.0/24"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			t.Setenv("BUSY_CLIENTS_EXCLUDE", tc.env)
			var c cli
			if err := parseArgs(&c, requiredArgs()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.Exclude, tc.want) {
				t.Fatalf("exclude = %q, want %q", c.Exclude, tc.want)
			}
		})
	}
}

func TestExecute_AFailedRunSendsAMessage(t *testing.T) {
	isolateEnv(t)
	srv, api := telegramServer(t)
	logs := &logBuffer{}
	if code := execute(context.Background(), requiredArgs("--timezone", "Not/AZone"), testLogger(logs), telegram.WithAPI(api)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	requests, _ := srv.Seen()
	if len(requests) != 1 || !strings.HasPrefix(requests[0].RichMessage.HTML, "<p>The busy-clients check failed on n2. The next scheduled run tries again.</p><p>Error: ") ||
		!strings.Contains(requests[0].RichMessage.HTML, "Not/AZone") {
		t.Fatalf("messages = %+v", requests)
	}
	if !strings.Contains(logs.String(), "the busy-clients check failed") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestExecute_TheFailureMessageOutlivesACancelledRun(t *testing.T) {
	isolateEnv(t)
	srv, api := telegramServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, requiredArgs(), testLogger(&logBuffer{}), telegram.WithAPI(api))
	}()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("execute did not return")
	}
	if requests, _ := srv.Seen(); len(requests) != 1 {
		t.Fatalf("messages = %d, want the failure message despite the cancelled run", len(requests))
	}
}

func TestExecute_BadSettingsOnlyLog(t *testing.T) {
	isolateEnv(t)
	srv, api := telegramServer(t)
	logs := &logBuffer{}
	if code := execute(context.Background(), requiredArgs("--node", ""), testLogger(logs), telegram.WithAPI(api)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if requests, _ := srv.Seen(); len(requests) != 0 || !strings.Contains(logs.String(), "because its settings cannot be read") {
		t.Fatalf("requests %d, logs %s", len(requests), logs.String())
	}
}

func TestExecute_WithoutTelegramItOnlyLogs(t *testing.T) {
	isolateEnv(t)
	srv, api := telegramServer(t)
	logs := &logBuffer{}
	if code := execute(context.Background(), requiredArgs("--telegram-chat", "0"), testLogger(logs), telegram.WithAPI(api)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if requests, _ := srv.Seen(); len(requests) != 0 || !strings.Contains(logs.String(), "because Telegram is not set up") {
		t.Fatalf("requests %d, logs %s", len(requests), logs.String())
	}
}

func TestExecute_AnEmptyBucketSettingFailsTheRunAndSaysSo(t *testing.T) {
	isolateEnv(t)
	srv, api := telegramServer(t)
	if code := execute(context.Background(), requiredArgs("--s3-bucket", ""), testLogger(&logBuffer{}), telegram.WithAPI(api)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	requests, _ := srv.Seen()
	if len(requests) != 1 || !strings.Contains(requests[0].RichMessage.HTML, "the setting --s3-bucket (TUNNELD_S3_BUCKET) is empty") {
		t.Fatalf("messages = %+v", requests)
	}
}
