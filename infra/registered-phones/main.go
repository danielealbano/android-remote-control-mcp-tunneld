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
	dateLayout      = "2006-01-02"
	defaultTextfile = "/var/lib/node_exporter/textfile_collector/arc_registered_phones.prom"
)

type cli struct {
	EnrolledSince    string `name:"enrolled-since" env:"REGISTERED_PHONES_ENROLLED_SINCE" required:"" help:"First UTC day (YYYY-MM-DD) whose enrollments are counted."`
	Textfile         string `name:"textfile" env:"REGISTERED_PHONES_TEXTFILE" default:"/var/lib/node_exporter/textfile_collector/arc_registered_phones.prom" help:"node_exporter textfile the dashboard box reads."`
	S3Endpoint       string `name:"s3-endpoint" env:"TUNNELD_S3_ENDPOINT" required:"" help:"S3 endpoint URL (tunneld's setting)."`
	S3Region         string `name:"s3-region" env:"TUNNELD_S3_REGION" default:"us-east-1" help:"S3 region (tunneld's setting)."`
	S3Bucket         string `name:"s3-bucket" env:"TUNNELD_S3_BUCKET" required:"" help:"Bucket holding the name registry (tunneld's setting)."`
	S3AccessKey      string `name:"s3-access-key" env:"TUNNELD_S3_ACCESS_KEY" required:"" help:"S3 access key (secret, tunneld's setting)."`
	S3SecretKey      string `name:"s3-secret-key" env:"TUNNELD_S3_SECRET_KEY" required:"" help:"S3 secret key (secret, tunneld's setting)."`
	S3ForcePathStyle bool   `name:"s3-force-path-style" env:"TUNNELD_S3_FORCE_PATH_STYLE" default:"true" negatable:"" help:"Path-style addressing (tunneld's setting)."`
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
		kong.Description("Counts the phones enrolled since a day that got a certificate, for the dashboard."),
	)
	if err != nil {
		return err
	}
	_, err = p.Parse(args)
	return err
}

func runOnce(ctx context.Context, c cli, logger *slog.Logger, opts ...jobOption) error {
	since, err := time.Parse(dateLayout, c.EnrolledSince)
	if err != nil {
		return fmt.Errorf("read the first counted day %q, which must be YYYY-MM-DD: %w", c.EnrolledSince, err)
	}
	j, err := newJob(jobConfig{
		Store: bucket.New(bucket.Config{
			Endpoint: c.S3Endpoint, Region: c.S3Region, Bucket: c.S3Bucket,
			AccessKey: c.S3AccessKey, SecretKey: c.S3SecretKey, ForcePathStyle: c.S3ForcePathStyle,
		}),
		EnrolledSince: since,
		Textfile:      c.Textfile,
		Logger:        logger,
	}, opts...)
	if err != nil {
		return err
	}
	return j.run(ctx)
}
