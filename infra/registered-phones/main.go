package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
)

const (
	dateLayout       = "2006-01-02"
	defaultTextfile  = "/var/lib/node_exporter/textfile_collector/arc_registered_phones.prom"
	defaultStateFile = "/var/lib/arc-registered-phones/state.json"
)

type cli struct {
	EnrolledSince string          `name:"enrolled-since" env:"REGISTERED_PHONES_ENROLLED_SINCE" required:"" help:"First UTC day (YYYY-MM-DD) whose enrollments are counted."`
	Textfile      string          `name:"textfile" env:"REGISTERED_PHONES_TEXTFILE" default:"/var/lib/node_exporter/textfile_collector/arc_registered_phones.prom" help:"node_exporter textfile the dashboard box reads."`
	StateFile     string          `name:"state-file" env:"REGISTERED_PHONES_STATE_FILE" default:"/var/lib/arc-registered-phones/state.json" help:"This node's copy of the state (the bucket holds the shared one)."`
	S3            bucket.Settings `embed:""`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], slog.New(slog.NewTextHandler(os.Stderr, nil)))
	stop()
	os.Exit(code)
}

const failedMsg = "the registered-phones count failed, so this node's dashboard file was not updated; the dashboard ignores counts more than two hours old"

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
		kong.Name("arc-registered-phones"),
		kong.Description("Keeps the count of the phones enrolled since a day that got a certificate, for the dashboard."),
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
	since, err := time.Parse(dateLayout, c.EnrolledSince)
	if err != nil {
		return fmt.Errorf("read the first counted day %q, which must be YYYY-MM-DD: %w", c.EnrolledSince, err)
	}
	j, err := newJob(jobConfig{
		Store:         bucket.New(bcfg),
		EnrolledSince: since,
		StateFile:     c.StateFile,
		Textfile:      c.Textfile,
		Logger:        logger,
	}, opts...)
	if err != nil {
		return err
	}
	return j.run(ctx)
}
