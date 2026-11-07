package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	richMessageBlocks  = 500
	richMessageRunes   = 32768
	telegramRetries    = 3
	telegramMaxBackoff = 60 * time.Second
)

type telegram struct {
	client *http.Client
	api    string
	token  string
	chat   int64
	sleep  func(context.Context, time.Duration) error
}

type telegramOption func(*telegram) error

func withTelegramAPI(base string) telegramOption {
	return func(t *telegram) error {
		if base == "" {
			return errors.New("the Telegram API address is empty")
		}
		t.api = strings.TrimRight(base, "/")
		return nil
	}
}

func withTelegramSleep(sleep func(context.Context, time.Duration) error) telegramOption {
	return func(t *telegram) error {
		if sleep == nil {
			return errors.New("the Telegram sleep function is missing")
		}
		t.sleep = sleep
		return nil
	}
}

func newTelegram(token string, chat int64, opts ...telegramOption) (*telegram, error) {
	if token == "" {
		return nil, errors.New("the Telegram bot token is empty")
	}
	if chat == 0 {
		return nil, errors.New("the Telegram chat id is missing")
	}
	t := &telegram{
		client: &http.Client{Timeout: 30 * time.Second},
		api:    "https://api.telegram.org",
		token:  token,
		chat:   chat,
		sleep:  sleepContext,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

type sendRichMessageRequest struct {
	ChatID      int64            `json:"chat_id"`
	RichMessage inputRichMessage `json:"rich_message"`
}

type inputRichMessage struct {
	HTML                string `json:"html"`
	SkipEntityDetection bool   `json:"skip_entity_detection"`
}

type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (t *telegram) Send(ctx context.Context, html string) error {
	body, err := json.Marshal(sendRichMessageRequest{ChatID: t.chat, RichMessage: inputRichMessage{HTML: html, SkipEntityDetection: true}})
	if err != nil {
		return fmt.Errorf("encode the Telegram message: %w", err)
	}
	for try := 0; ; try++ {
		wait, err := t.post(ctx, body)
		if err == nil {
			return nil
		}
		if wait <= 0 || wait > telegramMaxBackoff || try >= telegramRetries {
			return err
		}
		if serr := t.sleep(ctx, wait); serr != nil {
			return errors.Join(err, serr)
		}
	}
}

func (t *telegram) post(ctx context.Context, body []byte) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.api+"/bot"+t.token+"/sendRichMessage", bytes.NewReader(body))
	if err != nil {
		return 0, t.redact(fmt.Errorf("build the Telegram request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, t.redact(fmt.Errorf("send the Telegram request: %w", err))
	}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if cerr := resp.Body.Close(); cerr != nil {
		rerr = errors.Join(rerr, cerr)
	}
	if rerr != nil {
		return 0, t.redact(fmt.Errorf("read the Telegram answer (status %d): %w", resp.StatusCode, rerr))
	}
	var answer telegramResponse
	if err := json.Unmarshal(raw, &answer); err != nil {
		return 0, fmt.Errorf("decode the Telegram answer (status %d): %w", resp.StatusCode, err)
	}
	if answer.OK {
		return 0, nil
	}
	err = fmt.Errorf("telegram refused the message (status %d): %s", resp.StatusCode, answer.Description)
	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Duration(answer.Parameters.RetryAfter) * time.Second, err
	}
	return 0, err
}

func (t *telegram) redact(err error) error {
	return errors.New(strings.ReplaceAll(err.Error(), t.token, "<bot token>"))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
