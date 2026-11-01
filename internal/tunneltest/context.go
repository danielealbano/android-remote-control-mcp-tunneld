package tunneltest

import (
	"context"
	"sync"
)

type ExpiringCtx struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func NewExpiringCtx() *ExpiringCtx {
	return &ExpiringCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *ExpiringCtx) Done() <-chan struct{} { return c.done }

func (c *ExpiringCtx) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *ExpiringCtx) Expire() { c.once.Do(func() { close(c.done) }) }
