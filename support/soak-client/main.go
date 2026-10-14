package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/support/soak-client/soak"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := soak.Run(ctx, os.Args[1:], os.Stdout, logger)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "soak-client:", err)
		os.Exit(1)
	}
}
