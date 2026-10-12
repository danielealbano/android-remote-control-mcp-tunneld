package tunneltest

import (
	"context"
	"slices"

	"github.com/redis/go-redis/v9"
)

type failCommands struct {
	err   error
	names []string
}

func FailCommands(err error, names ...string) redis.Hook {
	return &failCommands{err: err, names: names}
}

func (h *failCommands) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *failCommands) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if slices.Contains(h.names, cmd.Name()) {
			cmd.SetErr(h.err)
			return h.err
		}
		return next(ctx, cmd)
	}
}

func (h *failCommands) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, c := range cmds {
			if slices.Contains(h.names, c.Name()) {
				for _, c := range cmds {
					c.SetErr(h.err)
				}
				return h.err
			}
		}
		return next(ctx, cmds)
	}
}

type cancelAfter struct {
	name   string
	cancel context.CancelFunc
}

func CancelAfter(name string, cancel context.CancelFunc) redis.Hook {
	return &cancelAfter{name: name, cancel: cancel}
}

func (h *cancelAfter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *cancelAfter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if cmd.Name() == h.name {
			h.cancel()
		}
		return err
	}
}

func (h *cancelAfter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
