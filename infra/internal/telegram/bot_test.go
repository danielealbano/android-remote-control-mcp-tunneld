package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram/telegramtest"
)

const testBotToken = "123:sekret-bot-token"

func newTestBot(t *testing.T, srv *telegramtest.Server, slept *[]time.Duration) *Bot {
	t.Helper()
	srv.T = t
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	b, err := New(testBotToken, 42,
		WithAPI(ts.URL),
		WithSleep(func(_ context.Context, d time.Duration) error {
			*slept = append(*slept, d)
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBot_SendPostsARichMessageWithoutEntityDetection(t *testing.T) {
	t.Parallel()
	srv := &telegramtest.Server{}
	var slept []time.Duration
	b := newTestBot(t, srv, &slept)
	if err := b.Send(context.Background(), "<p>hello</p>"); err != nil {
		t.Fatal(err)
	}
	want := telegramtest.Request{ChatID: 42, RichMessage: telegramtest.RichMessage{HTML: "<p>hello</p>", SkipEntityDetection: true}}
	requests, paths := srv.Seen()
	if len(requests) != 1 || requests[0] != want || paths[0] != "/bot"+testBotToken+"/sendRichMessage" {
		t.Fatalf("requests = %+v at %v, want %+v", requests, paths, want)
	}
}

func TestBot_SendRetriesWhenAskedToWait(t *testing.T) {
	t.Parallel()
	srv := &telegramtest.Server{Answers: []func(http.ResponseWriter) error{
		telegramtest.AnswerWith(http.StatusTooManyRequests, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 3","parameters":{"retry_after":3}}`),
	}}
	var slept []time.Duration
	b := newTestBot(t, srv, &slept)
	if err := b.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	requests, _ := srv.Seen()
	if len(requests) != 2 || len(slept) != 1 || slept[0] != 3*time.Second {
		t.Fatalf("requests %d, waits %v; want 2 requests after one 3 s wait", len(requests), slept)
	}
}

func TestBot_SendFails(t *testing.T) {
	t.Parallel()
	tooMany := telegramtest.AnswerWith(http.StatusTooManyRequests, `{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":1}}`)
	tests := []struct {
		name         string
		answers      []func(http.ResponseWriter) error
		wantRequests int
		wantErr      string
	}{
		{
			name:         "a refused message is an error carrying Telegram's reason",
			answers:      []func(http.ResponseWriter) error{telegramtest.AnswerWith(http.StatusBadRequest, `{"ok":false,"description":"Bad Request: chat not found"}`)},
			wantRequests: 1,
			wantErr:      "chat not found",
		},
		{
			name:         "repeated waits give up after the retries",
			answers:      []func(http.ResponseWriter) error{tooMany, tooMany, tooMany, tooMany, tooMany},
			wantRequests: retries + 1,
			wantErr:      "Too Many Requests",
		},
		{
			name:         "a wait longer than a minute is not waited for",
			answers:      []func(http.ResponseWriter) error{telegramtest.AnswerWith(http.StatusTooManyRequests, `{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":3600}}`)},
			wantRequests: 1,
			wantErr:      "Too Many Requests",
		},
		{
			name:         "an answer that is not JSON is an error",
			answers:      []func(http.ResponseWriter) error{telegramtest.AnswerWith(http.StatusBadGateway, `<html>bad gateway</html>`)},
			wantRequests: 1,
			wantErr:      "status 502",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := &telegramtest.Server{Answers: tc.answers}
			var slept []time.Duration
			b := newTestBot(t, srv, &slept)
			err := b.Send(context.Background(), "hello")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
			if requests, _ := srv.Seen(); len(requests) != tc.wantRequests {
				t.Fatalf("requests = %d, want %d", len(requests), tc.wantRequests)
			}
		})
	}
}

func TestBot_ErrorsNeverCarryTheToken(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.NotFoundHandler())
	ts.Close()
	b, err := New(testBotToken, 42, WithAPI(ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	err = b.Send(context.Background(), "hello")
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

func TestNew_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token string
		chat  int64
		opts  []Option
	}{
		{name: "empty token", token: "", chat: 42},
		{name: "missing chat", token: testBotToken, chat: 0},
		{name: "empty API address", token: testBotToken, chat: 42, opts: []Option{WithAPI("")}},
		{name: "missing sleep", token: testBotToken, chat: 42, opts: []Option{WithSleep(nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.token, tc.chat, tc.opts...); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
