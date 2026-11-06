package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExecute_AFailedRunSendsAMessage(t *testing.T) {
	t.Parallel()
	srv := &telegramServer{t: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	var logs bytes.Buffer
	c := cli{Node: "n2", Timezone: "Not/AZone", TelegramToken: testBotToken, TelegramChat: 42}
	code := execute(context.Background(), c, slog.New(slog.NewTextHandler(&logs, nil)), withTelegramAPI(ts.URL))
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	requests, _ := srv.seen()
	if len(requests) != 1 || !strings.Contains(requests[0].Text, "The refused-apps report failed on n2.") || !strings.Contains(requests[0].Text, "Not/AZone") {
		t.Fatalf("messages = %+v", requests)
	}
	if !strings.Contains(logs.String(), "the refused-apps report failed") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestExecute_WithoutTelegramItOnlyLogs(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	code := execute(context.Background(), cli{Node: "n2", Timezone: "UTC"}, slog.New(slog.NewTextHandler(&logs, nil)))
	if code != 1 || !strings.Contains(logs.String(), "because Telegram is not set up") {
		t.Fatalf("exit code %d, logs %s", code, logs.String())
	}
}

func TestExecute_TheFailureMessageOutlivesACancelledRun(t *testing.T) {
	t.Parallel()
	srv := &telegramServer{t: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := cli{Node: "n2", Timezone: "UTC", TelegramToken: testBotToken, TelegramChat: 42,
		S3Endpoint: "http://127.0.0.1:1", S3Region: "us-east-1", S3Bucket: "bucket", S3AccessKey: "k", S3SecretKey: "s",
		Textfile: "/nonexistent/x.prom"}
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, c, slog.New(slog.NewTextHandler(io.Discard, nil)), withTelegramAPI(ts.URL))
	}()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("execute did not return")
	}
	if requests, _ := srv.seen(); len(requests) != 1 {
		t.Fatalf("messages = %d, want the failure message despite the cancelled run", len(requests))
	}
}
