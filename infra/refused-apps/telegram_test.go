package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testBotToken = "123:sekret-bot-token"

type telegramServer struct {
	t        *testing.T
	mu       sync.Mutex
	answers  []func(http.ResponseWriter) error
	requests []sendRichMessageRequest
	paths    []string
}

func (s *telegramServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req sendRichMessageRequest
	if err := json.Unmarshal(body, &req); err != nil || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	s.paths = append(s.paths, r.URL.Path)
	answer := answerWith(http.StatusOK, `{"ok":true,"result":{}}`)
	if len(s.answers) > 0 {
		answer, s.answers = s.answers[0], s.answers[1:]
	}
	if err := answer(w); err != nil {
		s.t.Errorf("write the Telegram answer: %v", err)
	}
}

func (s *telegramServer) seen() ([]sendRichMessageRequest, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sendRichMessageRequest(nil), s.requests...), append([]string(nil), s.paths...)
}

func answerWith(code int, body string) func(http.ResponseWriter) error {
	return func(w http.ResponseWriter) error {
		w.WriteHeader(code)
		_, err := io.WriteString(w, body)
		return err
	}
}

func newTestTelegram(t *testing.T, srv *telegramServer, slept *[]time.Duration) *telegram {
	t.Helper()
	srv.t = t
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	tg, err := newTelegram(testBotToken, 42,
		withTelegramAPI(ts.URL),
		withTelegramSleep(func(_ context.Context, d time.Duration) error {
			*slept = append(*slept, d)
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestTelegram_SendPostsARichMessageWithoutEntityDetection(t *testing.T) {
	t.Parallel()
	srv := &telegramServer{}
	var slept []time.Duration
	tg := newTestTelegram(t, srv, &slept)
	if err := tg.Send(context.Background(), "<p>hello</p>"); err != nil {
		t.Fatal(err)
	}
	want := sendRichMessageRequest{ChatID: 42, RichMessage: inputRichMessage{HTML: "<p>hello</p>", SkipEntityDetection: true}}
	requests, paths := srv.seen()
	if len(requests) != 1 || requests[0] != want || paths[0] != "/bot"+testBotToken+"/sendRichMessage" {
		t.Fatalf("requests = %+v at %v, want %+v", requests, paths, want)
	}
}

func TestTelegram_SendRetriesWhenAskedToWait(t *testing.T) {
	t.Parallel()
	srv := &telegramServer{answers: []func(http.ResponseWriter) error{
		answerWith(http.StatusTooManyRequests, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 3","parameters":{"retry_after":3}}`),
	}}
	var slept []time.Duration
	tg := newTestTelegram(t, srv, &slept)
	if err := tg.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	requests, _ := srv.seen()
	if len(requests) != 2 || len(slept) != 1 || slept[0] != 3*time.Second {
		t.Fatalf("requests %d, waits %v; want 2 requests after one 3 s wait", len(requests), slept)
	}
}

func TestTelegram_SendFails(t *testing.T) {
	t.Parallel()
	tooMany := answerWith(http.StatusTooManyRequests, `{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":1}}`)
	tests := []struct {
		name         string
		answers      []func(http.ResponseWriter) error
		wantRequests int
		wantErr      string
	}{
		{
			name:         "a refused message is an error carrying Telegram's reason",
			answers:      []func(http.ResponseWriter) error{answerWith(http.StatusBadRequest, `{"ok":false,"description":"Bad Request: chat not found"}`)},
			wantRequests: 1,
			wantErr:      "chat not found",
		},
		{
			name:         "repeated waits give up after the retries",
			answers:      []func(http.ResponseWriter) error{tooMany, tooMany, tooMany, tooMany, tooMany},
			wantRequests: telegramRetries + 1,
			wantErr:      "Too Many Requests",
		},
		{
			name:         "a wait longer than a minute is not waited for",
			answers:      []func(http.ResponseWriter) error{answerWith(http.StatusTooManyRequests, `{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":3600}}`)},
			wantRequests: 1,
			wantErr:      "Too Many Requests",
		},
		{
			name:         "an answer that is not JSON is an error",
			answers:      []func(http.ResponseWriter) error{answerWith(http.StatusBadGateway, `<html>bad gateway</html>`)},
			wantRequests: 1,
			wantErr:      "status 502",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := &telegramServer{answers: tc.answers}
			var slept []time.Duration
			tg := newTestTelegram(t, srv, &slept)
			err := tg.Send(context.Background(), "hello")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
			if requests, _ := srv.seen(); len(requests) != tc.wantRequests {
				t.Fatalf("requests = %d, want %d", len(requests), tc.wantRequests)
			}
		})
	}
}

func TestTelegram_ErrorsNeverCarryTheToken(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.NotFoundHandler())
	ts.Close()
	tg, err := newTelegram(testBotToken, 42, withTelegramAPI(ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	err = tg.Send(context.Background(), "hello")
	if err == nil {
		t.Fatal("a closed server must fail")
	}
	if strings.Contains(err.Error(), "sekret-bot-token") {
		t.Fatalf("the error leaks the bot token: %v", err)
	}
	if !strings.Contains(err.Error(), "<bot token>") {
		t.Fatalf("the error should name the redacted address: %v", err)
	}
}

func TestNewTelegram_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token string
		chat  int64
		opts  []telegramOption
	}{
		{name: "empty token", token: "", chat: 42},
		{name: "missing chat", token: testBotToken, chat: 0},
		{name: "empty API address", token: testBotToken, chat: 42, opts: []telegramOption{withTelegramAPI("")}},
		{name: "missing sleep", token: testBotToken, chat: 42, opts: []telegramOption{withTelegramSleep(nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newTelegram(tc.token, tc.chat, tc.opts...); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
