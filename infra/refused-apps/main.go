package main

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
)

const failureErrorRunes = 4096

type cli struct {
	Node             string   `name:"node" env:"REFUSED_APPS_NODE" required:"" help:"Name of this node in the messages."`
	Timezone         string   `name:"timezone" env:"REFUSED_APPS_TIMEZONE" required:"" help:"Time zone of the report's days and times, for example UTC."`
	TelegramToken    string   `name:"telegram-token" env:"REFUSED_APPS_TELEGRAM_TOKEN" required:"" help:"Telegram bot token (secret)."`
	TelegramChat     int64    `name:"telegram-chat" env:"REFUSED_APPS_TELEGRAM_CHAT" required:"" help:"Telegram chat that receives the report."`
	Textfile         string   `name:"textfile" env:"REFUSED_APPS_TEXTFILE" default:"/var/lib/node_exporter/textfile_collector/arc_refused_apps.prom" help:"node_exporter textfile the dashboard table reads."`
	HideApps         []string `name:"hide-apps" env:"REFUSED_APPS_HIDE_APPS" help:"Comma-separated app ids kept on the attempt list but left out of the report and the dashboard."`
	AttestStatusURL  string   `name:"attest-status-url" env:"REFUSED_APPS_ATTEST_STATUS_URL" default:"https://android.googleapis.com/attestation/status" help:"Google attestation revocation-status endpoint."`
	S3Endpoint       string   `name:"s3-endpoint" env:"TUNNELD_S3_ENDPOINT" required:"" help:"S3 endpoint URL (tunneld's setting)."`
	S3Region         string   `name:"s3-region" env:"TUNNELD_S3_REGION" default:"us-east-1" help:"S3 region (tunneld's setting)."`
	S3Bucket         string   `name:"s3-bucket" env:"TUNNELD_S3_BUCKET" required:"" help:"Bucket holding the refusal records (tunneld's setting)."`
	S3AccessKey      string   `name:"s3-access-key" env:"TUNNELD_S3_ACCESS_KEY" required:"" help:"S3 access key (secret, tunneld's setting)."`
	S3SecretKey      string   `name:"s3-secret-key" env:"TUNNELD_S3_SECRET_KEY" required:"" help:"S3 secret key (secret, tunneld's setting)."`
	S3ForcePathStyle bool     `name:"s3-force-path-style" env:"TUNNELD_S3_FORCE_PATH_STYLE" default:"true" negatable:"" help:"Path-style addressing (tunneld's setting)."`
}

func main() {
	var c cli
	kong.Parse(&c,
		kong.Name("arc-refused-apps"),
		kong.Description("Sends the daily Telegram report of refused app enrollments and keeps the permanent attempt list."),
		kong.UsageOnError(),
	)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := execute(ctx, c, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, c cli, logger *slog.Logger, opts ...telegramOption) int {
	tg, err := newTelegram(c.TelegramToken, c.TelegramChat, opts...)
	if err != nil {
		logger.Error("the refused-apps report cannot run, because Telegram is not set up", "node", c.Node, "err", err)
		return 1
	}
	if err := runOnce(ctx, c, tg, logger); err != nil {
		logger.Error("the refused-apps report failed; the next scheduled run tries again", "node", c.Node, "err", err)
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		msg := fmt.Sprintf("<p>The refused-apps report failed on %s. The next scheduled run tries again.</p><p>Error: %s</p>",
			html.EscapeString(c.Node), html.EscapeString(clip(err.Error(), failureErrorRunes)))
		if serr := tg.Send(fctx, msg); serr != nil {
			logger.Error("could not send the message about the failed report", "node", c.Node, "err", serr)
		}
		return 1
	}
	return 0
}

func runOnce(ctx context.Context, c cli, tg messenger, logger *slog.Logger) error {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return fmt.Errorf("load the time zone %q: %w", c.Timezone, err)
	}
	statusClient := &http.Client{Timeout: 30 * time.Second}
	j, err := newJob(jobConfig{
		Store: newS3Bucket(bucketConfig{
			Endpoint: c.S3Endpoint, Region: c.S3Region, Bucket: c.S3Bucket,
			AccessKey: c.S3AccessKey, SecretKey: c.S3SecretKey, ForcePathStyle: c.S3ForcePathStyle,
		}),
		Messages: tg,
		Revocations: func(ctx context.Context) (revocationList, error) {
			return attest.NewStatusList(ctx, c.AttestStatusURL, statusClient, logger)
		},
		Node:     c.Node,
		Location: loc,
		Textfile: c.Textfile,
		HideApps: c.HideApps,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	return j.run(ctx)
}
