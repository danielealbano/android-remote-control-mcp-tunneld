// Command tunneld is the self-hosted end-to-end-encrypted tunnel server (see README.md).
package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/logging"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/server"
)

var version = "dev" // overridden via -ldflags at build time

// runServe is a seam so cmd/tunneld tests can assert CLI dispatch without a real server.
var runServe = server.Run

// CLI is the top-level kong command surface.
type CLI struct {
	Serve   config.ServeCmd `cmd:"" help:"Run the tunnel server."`
	Version struct{}        `cmd:"" help:"Print version and exit."`
}

func main() {
	var cli CLI
	kctx := kong.Parse(&cli,
		kong.Name("tunneld"),
		config.EnvTwins(),
		kong.UsageOnError(),
	)
	switch kctx.Command() {
	case "version":
		_, err := fmt.Println("tunneld", version)
		kctx.FatalIfErrorf(err)
		return
	case "serve":
		kctx.FatalIfErrorf(serve(cli.Serve))
	}
}

func serve(cfg config.ServeCmd) (err error) {
	logger, closeLogs, err := logging.New(cfg.Log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeLogs(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close log sinks: %w", cerr))
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runServe(ctx, cfg, logger, version)
}
