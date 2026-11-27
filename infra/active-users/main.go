package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
)

const (
	defaultTextfile  = "/var/lib/node_exporter/textfile_collector/arc_active_users.prom"
	defaultCacheFile = "/var/lib/arc-active-users/cache.json"
)

type cli struct {
	Textfile  string          `name:"textfile" env:"ACTIVE_USERS_TEXTFILE" default:"/var/lib/node_exporter/textfile_collector/arc_active_users.prom" help:"node_exporter textfile the dashboard reads."`
	CacheFile string          `name:"cache-file" env:"ACTIVE_USERS_CACHE_FILE" default:"/var/lib/arc-active-users/cache.json" help:"This node's cache of the lists of phones seen already read; a missing or unreadable cache is rebuilt from the bucket."`
	S3        bucket.Settings `embed:""`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], slog.New(slog.NewTextHandler(os.Stderr, nil)))
	stop()
	os.Exit(code)
}

const failedMsg = "the active-users count failed, so this node's dashboard file was not updated; the dashboard ignores counts more than an hour old"

func execute(ctx context.Context, args []string, logger *slog.Logger, opts ...jobOption) int {
	var c cli
	if err := parseArgs(&c, args); err != nil {
		logger.Error(failedMsg, "err", fmt.Errorf("read the settings: %w", err))
		return 1
	}
	if err := runOnce(ctx, c, logger, opts...); err != nil {
		logger.Error(failedMsg, "textfile", c.Textfile, "err", err)
		return 1
	}
	return 0
}

func parseArgs(c *cli, args []string) error {
	p, err := kong.New(c,
		kong.Name("arc-active-users"),
		kong.Description("Counts the phones seen in the last 24 hours, 7 days and 30 days from tunneld's lists, for the dashboard."),
	)
	if err != nil {
		return err
	}
	_, err = p.Parse(args)
	return err
}

func runOnce(ctx context.Context, c cli, logger *slog.Logger, opts ...jobOption) error {
	bcfg, err := c.S3.Config()
	if err != nil {
		return err
	}
	j, err := newJob(jobConfig{
		Store:     bucket.New(bcfg),
		CacheFile: c.CacheFile,
		Textfile:  c.Textfile,
		Logger:    logger,
	}, opts...)
	if err != nil {
		return err
	}
	return j.run(ctx)
}
