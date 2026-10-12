package tunneltest

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
)

func CloseOrLog(t testing.TB, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Logf("close %T: %v", c, err)
	}
}

func CloseLogged(c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		Logger().Warn("close failed", "type", fmt.Sprintf("%T", c), "err", err)
	}
}

func ServeHTTP(t testing.TB, srv *http.Server, ln net.Listener) {
	t.Helper()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		CloseOrLog(t, srv)
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("test HTTP server stopped unexpectedly: %v", err)
		}
	})
}

func Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
