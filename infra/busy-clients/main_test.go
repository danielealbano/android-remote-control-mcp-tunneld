package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram/telegramtest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
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

func TestLoadZone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		zone    string
		wantErr string
	}{
		{name: "UTC", zone: "UTC"},
		{name: "a named zone", zone: "Europe/Zurich"},
		{name: "an empty zone", zone: "", wantErr: `the time zone "" is not a named zone`},
		{name: "the local zone", zone: "Local", wantErr: `the time zone "Local" is not a named zone`},
		{name: "an unknown zone", zone: "Not/AZone", wantErr: `load the time zone "Not/AZone"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			loc, err := loadZone(tc.zone)
			if tc.wantErr == "" {
				if err != nil || loc.String() != tc.zone {
					t.Fatalf("loadZone(%q) = %v, %v", tc.zone, loc, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
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

type fakeBucket struct {
	mu    sync.Mutex
	logs  map[string][]byte
	state []byte
}

func (b *fakeBucket) saved() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func bucketServer(t *testing.T, b *fakeBucket) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(code int, body string) {
			w.WriteHeader(code)
			if _, err := io.WriteString(w, body); err != nil {
				t.Errorf("write the S3 answer: %v", err)
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/bucket":
			var list strings.Builder
			list.WriteString(`<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated>`)
			for k := range b.logs {
				if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
					list.WriteString("<Contents><Key>" + k + "</Key></Contents>")
				}
			}
			list.WriteString("</ListBucketResult>")
			write(http.StatusOK, list.String())
		case r.Method == http.MethodGet && key == stateKey:
			if b.state == nil {
				write(http.StatusNotFound, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
				return
			}
			write(http.StatusOK, string(b.state))
		case r.Method == http.MethodGet && b.logs[key] != nil:
			write(http.StatusOK, string(b.logs[key]))
		case r.Method == http.MethodPut && key == stateKey:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				write(http.StatusBadRequest, err.Error())
				return
			}
			b.state = body
			write(http.StatusOK, "")
		default:
			write(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestExecute_AlertsEndToEnd(t *testing.T) {
	isolateEnv(t)
	now := time.Now().UTC()
	at := now.Add(-time.Hour)
	var events []store.Event
	events = append(events, busy("198.51.100.1", 4, 1, at)...)
	events = append(events, busy("198.51.100.2", 3, 2, at)...)
	events = append(events, busy("198.51.100.3", 3, 1, at)...)
	events = append(events, busy("198.51.100.4", 2, 2, at)...)
	events = append(events, busy("192.0.2.5", 10, 5, at)...)
	events = append(events, busy("198.51.100.200", 10, 5, at)...)
	events = append(events, busy("203.0.113.9", 10, 5, at)...)
	var log strings.Builder
	for _, ev := range events {
		line, err := jsonLine(ev)
		if err != nil {
			t.Fatal(err)
		}
		log.WriteString(line + "\n")
	}
	b := &fakeBucket{logs: map[string][]byte{logKey(now.Add(-2*time.Hour), "0123456789abcdef"): []byte(log.String())}}
	s3 := bucketServer(t, b)
	sources := rangeServer(t, map[string]string{
		"/chatgpt.json": `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`,
		"/page":         `<h2 id="outbound-ip-addresses">Outbound</h2><p><code>198.51.100.192/26</code></p><h3 id="phased-out-ip-addresses">Phased out</h3>`,
	}, nil)
	srv, api := telegramServer(t)
	logs := &logBuffer{}
	args := requiredArgs("--s3-endpoint", s3, "--s3-bucket", "bucket", "--daily-hour", "0", "--connections", "4", "--spread-connections", "3",
		"--spread-tunnels", "2", "--exclude", "203.0.113.9", "--openai-ranges", sources+"/chatgpt.json", "--anthropic-ranges", sources+"/page")
	if code := execute(context.Background(), args, testLogger(logs), telegram.WithAPI(api)); code != 0 {
		t.Fatalf("exit code = %d, want 0; logs %s", code, logs.String())
	}
	after := time.Now().UTC()
	requests, _ := srv.Seen()
	if len(requests) != 2 {
		t.Fatalf("messages = %+v, want the alert and the daily line", requests)
	}
	alertHTML := requests[0].RichMessage.HTML
	first, second := strings.Index(alertHTML, ">198.51.100.1<"), strings.Index(alertHTML, ">198.51.100.2<")
	if !strings.Contains(alertHTML, "2 new addresses") || first < 0 || second < 0 || first > second {
		t.Fatalf("alert = %s", alertHTML)
	}
	for _, left := range []string{"198.51.100.3", "198.51.100.4", "192.0.2.5", "198.51.100.200", "203.0.113.9"} {
		if strings.Contains(alertHTML, left) {
			t.Fatalf("the alert names %s: %s", left, alertHTML)
		}
	}
	if !strings.HasPrefix(requests[1].RichMessage.HTML, "<p>The busy-clients check is running (from n2): 2 addresses alerted in the last 24 hours, 2 on file.</p>") {
		t.Fatalf("daily line = %s", requests[1].RichMessage.HTML)
	}
	var saved alertedList
	if err := json.Unmarshal(b.saved(), &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Addresses) != 2 || saved.LastDaily != now.Format(dateLayout) && saved.LastDaily != after.Format(dateLayout) {
		t.Fatalf("saved = %+v", saved)
	}
}

func TestExecute_AFailureMessageThatCannotBeSentIsLogged(t *testing.T) {
	isolateEnv(t)
	srv := &telegramtest.Server{T: t, Answers: []func(http.ResponseWriter) error{
		telegramtest.AnswerWith(http.StatusBadRequest, `{"ok":false,"description":"Bad Request: chat not found"}`),
	}}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	logs := &logBuffer{}
	if code := execute(context.Background(), requiredArgs("--timezone", "Not/AZone"), testLogger(logs), telegram.WithAPI(ts.URL)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(logs.String(), "could not send the message about the failed check") || !strings.Contains(logs.String(), "chat not found") {
		t.Fatalf("logs = %s", logs.String())
	}
}
