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
	mu     sync.Mutex
	counts map[string]int
}

func NewLogCounter() *LogCounter { return &LogCounter{counts: map[string]int{}} }

func (c *LogCounter) Logger() *slog.Logger { return slog.New(c) }

func (c *LogCounter) Enabled(context.Context, slog.Level) bool { return true }

func (c *LogCounter) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.counts[r.Message]++
	c.mu.Unlock()
	return nil
}

func (c *LogCounter) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *LogCounter) WithGroup(string) slog.Handler { return c }

func (c *LogCounter) Count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[msg]
}
