//go:build integration || e2e || staging

package tunneltest

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

func ServesCertificate(edgeAddr, host string) bool {
	var presented bool
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", edgeAddr, &tls.Config{
		ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			presented = len(cs.PeerCertificates) > 0
			return nil
		},
	})
	if err == nil {
		_ = conn.Close()
	}
	return presented
}

func WaitReservedHosts(t *testing.T, edgeAddr string, hosts []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for _, host := range hosts {
		for !ServesCertificate(edgeAddr, host) {
			if time.Now().After(deadline) {
				t.Fatalf("reserved host %s served no certificate within %s", host, timeout)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

type LogCounter struct {
	state *logCounts
	next  slog.Handler
}

type logCounts struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewLogCounter(next slog.Handler) *LogCounter {
	return &LogCounter{state: &logCounts{counts: map[string]int{}}, next: next}
}

func (c *LogCounter) Logger() *slog.Logger { return slog.New(c) }

func (c *LogCounter) Enabled(context.Context, slog.Level) bool { return true }

func (c *LogCounter) Handle(ctx context.Context, r slog.Record) error {
	c.state.mu.Lock()
	c.state.counts[r.Message]++
	c.state.mu.Unlock()
	if !c.next.Enabled(ctx, r.Level) {
		return nil
	}
	return c.next.Handle(ctx, r)
}

func (c *LogCounter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogCounter{state: c.state, next: c.next.WithAttrs(attrs)}
}

func (c *LogCounter) WithGroup(name string) slog.Handler {
	return &LogCounter{state: c.state, next: c.next.WithGroup(name)}
}

func (c *LogCounter) Count(msg string) int {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return c.state.counts[msg]
}
