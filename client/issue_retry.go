package client

import (
	"context"
	"errors"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func issueRetryWait(err error, retry int) (time.Duration, bool) {
	if ee, ok := errors.AsType[*EnrollError](err); ok {
		if !ee.Retryable {
			return 0, false
		}
		if ee.RetryAfter > 0 {
			return ee.RetryAfter, true
		}
		return wire.IssueRetryWait(retry), true
	}
	if _, ok := errors.AsType[*transportError](err); ok {
		return wire.IssueRetryWait(retry), true
	}
	return 0, false
}

func issueWithRetries(ctx context.Context, sleep func(context.Context, time.Duration) error, nonce string,
	issue func(nonce string) (*Identity, error), freshNonce func() (string, error)) (*Identity, error) {
	id, err := issue(nonce)
	for retry := 0; err != nil; retry++ {
		wait, ok := issueRetryWait(err, retry)
		if !ok || retry >= wire.IssueRetries {
			return nil, err
		}
		if serr := sleep(ctx, wait); serr != nil {
			return nil, errors.Join(err, serr)
		}
		var n string
		if n, err = freshNonce(); err == nil {
			id, err = issue(n)
		}
	}
	return id, nil
}
