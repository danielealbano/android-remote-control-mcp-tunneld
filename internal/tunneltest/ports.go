package tunneltest

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	freePortFloor = 10000
	freePortTries = 100
)

func FreeAddr(t *testing.T) string {
	t.Helper()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(FreePort(t, "127.0.0.1")))
}

func FreePort(t *testing.T, ip string) int {
	t.Helper()
	ceiling := ephemeralLow(t)
	for range freePortTries {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling-freePortFloor)))
		if err != nil {
			t.Fatalf("pick a free port: %v", err)
		}
		port := freePortFloor + int(n.Int64())
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatalf("free port on %s: %v", ip, err)
		}
		if err := ln.Close(); err != nil {
			t.Fatalf("release port probe on %s: %v", ip, err)
		}
		return port
	}
	t.Fatalf("no free port in [%d, %d) on %s after %d tries", freePortFloor, ceiling, ip, freePortTries)
	return 0
}

func ephemeralLow(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Fatalf("read the ephemeral port range: %v", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Fatalf("unexpected ephemeral port range %q", raw)
	}
	low, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("parse the ephemeral port range %q: %v", raw, err)
	}
	if low <= freePortFloor {
		t.Fatalf("the ephemeral port range starts at %d, at or below the test port floor %d", low, freePortFloor)
	}
	return low
}
