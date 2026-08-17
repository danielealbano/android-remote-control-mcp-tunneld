package clientip

import (
	"net/http"
	"testing"
)

func req(header, value string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

func TestTrustedIP_MappedAndZoned(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		hval     string
		wantAddr string
	}{
		{"mapped ipv4", "X-Real-Ip", "::ffff:1.2.3.4", "1.2.3.4"},
		{"bare ipv6", "X-Real-Ip", "2001:db8::1", "2001:db8::1"},
		{"zoned stripped", "X-Real-Ip", "fe80::1%eth0", "fe80::1"},
		{"rightmost xff mapped", "X-Forwarded-For", "9.9.9.9, ::ffff:1.2.3.4", "1.2.3.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := TrustedIP(req(tc.header, tc.hval), tc.header)
			if !ok {
				t.Fatalf("expected ok for %q", tc.hval)
			}
			if addr.String() != tc.wantAddr {
				t.Errorf("addr = %s, want %s", addr, tc.wantAddr)
			}
		})
	}
}

func TestTrustedIP(t *testing.T) {
	tests := []struct {
		name         string
		header, hval string
		lookup       string
		wantOK       bool
		wantAddr     string
	}{
		{"single value cf", "Cf-Connecting-Ip", "9.9.9.9", "Cf-Connecting-Ip", true, "9.9.9.9"},
		{"right-most xff", "X-Forwarded-For", "1.2.3.4, 9.9.9.9", "X-Forwarded-For", true, "9.9.9.9"},
		{"absent header", "", "", "X-Real-Ip", false, ""},
		{"unparseable", "X-Real-Ip", "not-an-ip", "X-Real-Ip", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := TrustedIP(req(tc.header, tc.hval), tc.lookup)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && addr.String() != tc.wantAddr {
				t.Errorf("addr = %s, want %s", addr, tc.wantAddr)
			}
		})
	}
}
