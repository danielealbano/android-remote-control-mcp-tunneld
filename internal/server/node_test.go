package server

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestHostname_FallsBackAndLogs(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		err     error
		wantLog bool
	}{
		{name: "lookup fails", err: errors.New("uname failed"), wantLog: true},
		{name: "empty hostname", wantLog: true},
		{name: "hostname available", host: "edge-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			got := hostname(func() (string, error) { return tc.host, tc.err }, slog.New(slog.NewTextHandler(&buf, nil)))
			logged := strings.Contains(buf.String(), `msg="OS hostname unavailable (using a random node name)"`)
			if logged != tc.wantLog {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLog, buf.String())
			}
			if !tc.wantLog {
				if got != tc.host {
					t.Fatalf("hostname = %q, want %q", got, tc.host)
				}
				return
			}
			if !strings.HasPrefix(got, "node-") || len(got) != len("node-")+6 {
				t.Fatalf("hostname = %q, want a node-<6 hex> fallback", got)
			}
			if !strings.Contains(buf.String(), "fallback="+got) {
				t.Fatalf("the fallback name must be logged; log = %q", buf.String())
			}
		})
	}
}
