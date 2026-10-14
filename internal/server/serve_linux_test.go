package server

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestListenPublic_SetsKeepAlive(t *testing.T) {
	ln, err := listenPublic(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, ln)
	dialed := make(chan net.Conn, 1)
	go func() {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Errorf("dial: %v", derr)
			dialed <- nil
			return
		}
		dialed <- c
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, c)
	if peer := <-dialed; peer != nil {
		defer tunneltest.CloseOrLog(t, peer)
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted %T, want *net.TCPConn", c)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	opts := []struct {
		name       string
		level, opt int
		want       int
	}{
		{name: "SO_KEEPALIVE", level: syscall.SOL_SOCKET, opt: syscall.SO_KEEPALIVE, want: 1},
		{name: "TCP_KEEPIDLE", level: syscall.IPPROTO_TCP, opt: syscall.TCP_KEEPIDLE, want: 10},
		{name: "TCP_KEEPINTVL", level: syscall.IPPROTO_TCP, opt: syscall.TCP_KEEPINTVL, want: 5},
		{name: "TCP_KEEPCNT", level: syscall.IPPROTO_TCP, opt: syscall.TCP_KEEPCNT, want: 3},
	}
	var getErr error
	got := make([]int, len(opts))
	if cerr := raw.Control(func(fd uintptr) {
		for i, o := range opts {
			v, gerr := syscall.GetsockoptInt(int(fd), o.level, o.opt)
			if gerr != nil {
				getErr = errors.Join(getErr, gerr)
				continue
			}
			got[i] = v
		}
	}); cerr != nil {
		t.Fatal(cerr)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	for i, o := range opts {
		if got[i] != o.want {
			t.Errorf("%s = %d, want %d", o.name, got[i], o.want)
		}
	}
}
