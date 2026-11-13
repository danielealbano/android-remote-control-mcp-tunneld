package main

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

const failureErrorRunes = 4096

type cli struct {
	Node              string          `name:"node" env:"BUSY_CLIENTS_NODE" required:"" help:"Name of this node in the messages."`
	Timezone          string          `name:"timezone" env:"BUSY_CLIENTS_TIMEZONE" required:"" help:"Time zone of the times in the messages and of the daily line's hour, for example UTC."`
	DailyHour         int             `name:"daily-hour" env:"BUSY_CLIENTS_DAILY_HOUR" required:"" help:"Hour (0-23) from which the first run of the day sends the daily still-running line."`
	TelegramToken     string          `name:"telegram-token" env:"BUSY_CLIENTS_TELEGRAM_TOKEN" required:"" help:"Telegram bot token (secret)."`
	TelegramChat      int64           `name:"telegram-chat" env:"BUSY_CLIENTS_TELEGRAM_CHAT" required:"" help:"Telegram chat that receives the alerts."`
	Exclude           []string        `name:"exclude" env:"BUSY_CLIENTS_EXCLUDE" help:"Comma-separated addresses or CIDR ranges that are never counted."`
	Connections       int             `name:"connections" env:"BUSY_CLIENTS_CONNECTIONS" default:"500" help:"Connections in 24 hours that flag an address."`
	SpreadConnections int             `name:"spread-connections" env:"BUSY_CLIENTS_SPREAD_CONNECTIONS" default:"100" help:"Connections in 24 hours that flag an address reaching --spread-tunnels tunnels."`
	SpreadTunnels     int             `name:"spread-tunnels" env:"BUSY_CLIENTS_SPREAD_TUNNELS" default:"3" help:"Tunnels an address must reach to be flagged at --spread-connections."`
	OpenAIRanges      []string        `name:"openai-ranges" env:"BUSY_CLIENTS_OPENAI_RANGES" default:"https://openai.com/chatgpt-connectors.json,https://openai.com/chatgpt-actions.json,https://openai.com/chatgpt-user.json" help:"OpenAI's published ChatGPT address lists (JSON), left out of the counts."`
	AnthropicRanges   string          `name:"anthropic-ranges" env:"BUSY_CLIENTS_ANTHROPIC_RANGES" default:"https://platform.claude.com/docs/en/api/ip-addresses" help:"Anthropic's published address page, whose outbound ranges are left out of the counts."`
	CountryFile       string          `name:"country-file" env:"BUSY_CLIENTS_COUNTRY_FILE" default:"/srv/tunneld/banfiles/dbip-country-lite.csv" help:"DB-IP Country Lite CSV that gives each alerted address its country (the file tunneld's country bans use)."`
	OwnerLookup       string          `name:"owner-lookup" env:"BUSY_CLIENTS_OWNER_LOOKUP" default:"https://stat.ripe.net/data/prefix-overview/data.json" help:"RIPEstat prefix-overview address that gives each alerted address its network owner."`
	S3                bucket.Settings `embed:""`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], slog.New(slog.NewTextHandler(os.Stderr, nil)))
	stop()
	os.Exit(code)
}

func parseArgs(c *cli, args []string) error {
	p, err := kong.New(c,
		kong.Name("arc-busy-clients"),
		kong.Description("Sends a Telegram alert, once per address, for each client address with unusually many tunnel connections in the last 24 hours."),
	)
	if err != nil {
		return err
	}
	_, err = p.Parse(args)
	return err
}

func execute(ctx context.Context, args []string, logger *slog.Logger, opts ...telegram.Option) int {
	var c cli
	if err := parseArgs(&c, args); err != nil {
		logger.Error("the busy-clients check cannot run, because its settings cannot be read", "err", err)
		return 1
	}
	bot, err := telegram.New(c.TelegramToken, c.TelegramChat, opts...)
	if err != nil {
		logger.Error("the busy-clients check cannot run, because Telegram is not set up", "node", c.Node, "err", err)
		return 1
	}
	if err := runOnce(ctx, c, bot, logger); err != nil {
		logger.Error("the busy-clients check failed and stopped before it finished", "node", c.Node, "err", err)
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		msg := fmt.Sprintf("<p>The busy-clients check failed on %s and stopped before it finished.</p><p>Error: %s</p>",
			html.EscapeString(c.Node), html.EscapeString(telegram.Clip(err.Error(), failureErrorRunes)))
		if serr := bot.Send(fctx, msg); serr != nil {
			logger.Error("could not send the message about the failed check", "node", c.Node, "err", serr)
		}
		return 1
	}
	return 0
}

func loadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" {
		return nil, fmt.Errorf("the time zone %q is not a named zone such as UTC or Europe/Zurich", name)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("load the time zone %q: %w", name, err)
	}
	return loc, nil
}

func bucketConfig(s bucket.Settings) (bucket.Config, error) {
	cfg, err := s.Config()
	if err != nil {
		return bucket.Config{}, err
	}
	cfg.Timeout = defaultTimeout
	return cfg, nil
}

func runOnce(ctx context.Context, c cli, msgs messenger, logger *slog.Logger) error {
	loc, err := loadZone(c.Timezone)
	if err != nil {
		return err
	}
	bcfg, err := bucketConfig(c.S3)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	j, err := newJob(jobConfig{
		Store:    bucket.New(bcfg),
		Messages: msgs,
		Ranges: func(ctx context.Context) ([]netip.Prefix, error) {
			return loadRanges(ctx, client, logger.With("node", c.Node), c.OpenAIRanges, c.AnthropicRanges)
		},
		Locate:    newLocator(client, logger.With("node", c.Node), c.CountryFile, c.OwnerLookup),
		Exclude:   c.Exclude,
		Rule:      rule{connections: c.Connections, spreadConnections: c.SpreadConnections, spreadTunnels: c.SpreadTunnels},
		DailyHour: c.DailyHour,
		Node:      c.Node,
		Location:  loc,
		Logger:    logger,
	})
	if err != nil {
		return err
	}
	return j.run(ctx)
}
