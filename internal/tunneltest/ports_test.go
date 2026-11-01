package tunneltest

import (
	"net"
	"strconv"
	"testing"
)

func TestFreePort_BelowTheEphemeralRange(t *testing.T) {
	t.Parallel()
	ceiling := ephemeralLow(t)
	for range 20 {
		port := FreePort(t, "127.0.0.1")
		if port < freePortFloor || port >= ceiling {
			t.Fatalf("FreePort = %d, want a port in [%d, %d): the kernel never hands those out as ephemeral source ports", port, freePortFloor, ceiling)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("the returned port %d must be bindable: %v", port, err)
		}
		CloseOrLog(t, ln)
	}
}

func TestFreeAddr_IsLoopbackBelowTheEphemeralRange(t *testing.T) {
	t.Parallel()
	host, portStr, err := net.SplitHostPort(FreeAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port < freePortFloor || port >= ephemeralLow(t) {
		t.Fatalf("FreeAddr = %s:%d, want 127.0.0.1 with a port below the ephemeral range", host, port)
	}
}
