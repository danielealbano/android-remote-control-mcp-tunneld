package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram/telegramtest"
)

const testBotToken = "123:sekret-bot-token"

func TestCLI_HideAppsFromTheEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{name: "an empty setting hides nothing", env: "", want: nil},
		{name: "a comma separates the app ids", env: "dev.example.own,dev.example.own.debug", want: []string{"dev.example.own", "dev.example.own.debug"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REFUSED_APPS_HIDE_APPS", tc.env)
			var c cli
			p, err := kong.New(&c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Parse([]string{"--node=n1", "--timezone=UTC", "--telegram-token=x", "--telegram-chat=1",
				"--s3-endpoint=http://127.0.0.1:1", "--s3-bucket=b", "--s3-access-key=k", "--s3-secret-key=s"}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.HideApps, tc.want) {
				t.Fatalf("hidden apps = %q, want %q", c.HideApps, tc.want)
			}
		})
	}
}

func TestExecute_AFailedRunSendsAMessage(t *testing.T) {
	t.Parallel()
	srv := &telegramtest.Server{T: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	var logs bytes.Buffer
	c := cli{Node: "n2", Timezone: "Not/AZone", TelegramToken: testBotToken, TelegramChat: 42}
	code := execute(context.Background(), c, slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, &logs), nil)), telegram.WithAPI(ts.URL))
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	requests, _ := srv.Seen()
	if len(requests) != 1 || !strings.HasPrefix(requests[0].RichMessage.HTML, "<p>The refused-apps report failed on n2. The next scheduled run tries again.</p><p>Error: ") ||
		!strings.Contains(requests[0].RichMessage.HTML, "Not/AZone") {
		t.Fatalf("messages = %+v", requests)
	}
	if !strings.Contains(logs.String(), "the refused-apps report failed") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestExecute_AnEmptyBucketSettingFailsTheRunAndSaysSo(t *testing.T) {
	t.Parallel()
	srv := &telegramtest.Server{T: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := cli{Node: "n2", Timezone: "UTC", TelegramToken: testBotToken, TelegramChat: 42,
		S3: bucket.Settings{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", AccessKey: "k", SecretKey: "s"}}
	if code := execute(context.Background(), c, testLog(), telegram.WithAPI(ts.URL)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	requests, _ := srv.Seen()
	if len(requests) != 1 || !strings.Contains(requests[0].RichMessage.HTML, "the setting --s3-bucket (TUNNELD_S3_BUCKET) is empty") {
		t.Fatalf("messages = %+v", requests)
	}
}

func TestExecute_WithoutTelegramItOnlyLogs(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	code := execute(context.Background(), cli{Node: "n2", Timezone: "UTC"}, slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, &logs), nil)))
	if code != 1 || !strings.Contains(logs.String(), "because Telegram is not set up") {
		t.Fatalf("exit code %d, logs %s", code, logs.String())
	}
}

func TestExecute_TheFailureMessageOutlivesACancelledRun(t *testing.T) {
	t.Parallel()
	srv := &telegramtest.Server{T: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := cli{Node: "n2", Timezone: "UTC", TelegramToken: testBotToken, TelegramChat: 42,
		S3:       bucket.Settings{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", Bucket: "bucket", AccessKey: "k", SecretKey: "s"},
		Textfile: "/nonexistent/x.prom"}
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, c, testLog(), telegram.WithAPI(ts.URL))
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
