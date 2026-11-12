package telegramtest

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
)

type RichMessage struct {
	HTML                string `json:"html"`
	SkipEntityDetection bool   `json:"skip_entity_detection"`
}

type Request struct {
	ChatID      int64       `json:"chat_id"`
	RichMessage RichMessage `json:"rich_message"`
}

type Server struct {
	T        *testing.T
	Answers  []func(http.ResponseWriter) error
	mu       sync.Mutex
	requests []Request
	paths    []string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	s.paths = append(s.paths, r.URL.Path)
	answer := AnswerWith(http.StatusOK, `{"ok":true,"result":{}}`)
	if len(s.Answers) > 0 {
		answer, s.Answers = s.Answers[0], s.Answers[1:]
	}
	if err := answer(w); err != nil {
		s.T.Errorf("write the Telegram answer: %v", err)
	}
}

func (s *Server) Seen() ([]Request, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...), append([]string(nil), s.paths...)
}

func AnswerWith(code int, body string) func(http.ResponseWriter) error {
	return func(w http.ResponseWriter) error {
		w.WriteHeader(code)
		_, err := io.WriteString(w, body)
		return err
	}
}
