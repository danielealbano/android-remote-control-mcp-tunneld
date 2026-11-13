package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testCountries = "start_ip,end_ip,country\n" +
	"not,a,row\n" +
	"192.0.2.0,192.0.2.255,nl\n" +
	"198.51.100.0,198.51.100.127,US\n" +
	"2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,CH\n" +
	"203.0.113.10,203.0.113.0,XX\n" +
	"10.0.0.0,2001:db9::,YY\n" +
	"\"broken\n"

func writeCountries(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dbip-country-lite.csv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCountries_SkipsBadRowsAndSorts(t *testing.T) {
	t.Parallel()
	ranges, err := loadCountries(writeCountries(t, testCountries))
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, r := range ranges {
		codes = append(codes, r.code)
	}
	if !reflect.DeepEqual(codes, []string{"NL", "US", "CH"}) {
		t.Fatalf("codes = %v, want the three valid rows in address order", codes)
	}
}

func TestLoadCountries_Failures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string
	}{
		{name: "a missing file", path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.csv") }, wantErr: "open the DB-IP country file"},
		{name: "a file without a valid row", path: func(t *testing.T) string { return writeCountries(t, "a,b,c\n1.2.3,x,y\n") }, wantErr: "has no valid row"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadCountries(tc.path(t)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestCountryOf(t *testing.T) {
	t.Parallel()
	ranges, err := loadCountries(writeCountries(t, testCountries))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "the first address of a range", addr: "192.0.2.0", want: "NL"},
		{name: "the last address of a range", addr: "192.0.2.255", want: "NL"},
		{name: "inside another range", addr: "198.51.100.7", want: "US"},
		{name: "in a gap between ranges", addr: "198.51.100.200", want: ""},
		{name: "before the first range", addr: "10.0.0.1", want: ""},
		{name: "an IPv4 address after the last IPv4 range", addr: "203.0.113.5", want: ""},
		{name: "an IPv6 address", addr: "2001:db8:1:2::5", want: "CH"},
		{name: "an IPv6 address before any IPv6 range", addr: "::1", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := countryOf(ranges, netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Fatalf("countryOf(%s) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func ownerServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(answer))
	t.Cleanup(ts.Close)
	return ts.URL + "/data/prefix-overview/data.json"
}

func writeAnswer(t *testing.T, w http.ResponseWriter, code int, body string) {
	t.Helper()
	w.WriteHeader(code)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("write the answer: %v", err)
	}
}

func TestLookupOwner(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("n", ownerRunes)
	tests := []struct {
		name    string
		code    int
		body    string
		want    string
		wantErr string
	}{
		{name: "one network", code: 200, body: `{"data":{"asns":[{"asn":64500,"holder":"EXAMPLE Example GmbH"}]}}`, want: "AS64500 EXAMPLE Example GmbH"},
		{name: "two networks", code: 200, body: `{"data":{"asns":[{"asn":64500,"holder":"A"},{"asn":64501,"holder":"B"}]}}`, want: "AS64500 A, AS64501 B"},
		{name: "no announcing network", code: 200, body: `{"data":{"asns":[]}}`, want: "not announced"},
		{name: "control characters are replaced", code: 200, body: `{"data":{"asns":[{"asn":64500,"holder":"A\u202eB"}]}}`, want: "AS64500 A\uFFFDB"},
		{name: "a long name is clipped", code: 200, body: `{"data":{"asns":[{"asn":64500,"holder":"` + long + `"}]}}`, want: ("AS64500 " + long)[:ownerRunes] + "…"},
		{name: "an answer that is not 200", code: 503, body: "busy", wantErr: "status 503"},
		{name: "an answer that is not JSON", code: 200, body: "<html>", wantErr: "decode the network owner of 192.0.2.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu    sync.Mutex
				query string
			)
			base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				query = r.URL.RawQuery
				mu.Unlock()
				writeAnswer(t, w, tc.code, tc.body)
			})
			got, err := lookupOwner(context.Background(), &http.Client{Timeout: 5 * time.Second}, base, netip.MustParseAddr("192.0.2.7"))
			mu.Lock()
			defer mu.Unlock()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want || query != "resource=192.0.2.7&sourceapp=arc-busy-clients" {
				t.Fatalf("lookupOwner = %q, %v with query %q; want %q", got, err, query, tc.want)
			}
		})
	}
}

func TestNewLocator_GivesCountriesAndOwners(t *testing.T) {
	t.Parallel()
	base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("resource") {
		case "198.51.100.7":
			writeAnswer(t, w, 500, "broken")
		default:
			writeAnswer(t, w, 200, `{"data":{"asns":[{"asn":64500,"holder":"Owner of `+r.URL.Query().Get("resource")+`"}]}}`)
		}
	})
	logs := &logBuffer{}
	locate := newLocator(&http.Client{Timeout: 5 * time.Second}, testLogger(logs), writeCountries(t, testCountries), base)
	got := locate(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.5")})
	want := []place{
		{country: "NL", network: "AS64500 Owner of 192.0.2.7"},
		{country: "US", network: unknownPlace},
		{country: unknownPlace, network: "AS64500 Owner of 203.0.113.5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("places = %+v\nwant     %+v", got, want)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="the network owners of some addresses could not be looked up, so they show as unknown"`) ||
		!strings.Contains(logs.String(), "addresses=1 of=3") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestNewLocator_WithoutTheCountryFileShowsUnknownCountries(t *testing.T) {
	t.Parallel()
	base := ownerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeAnswer(t, w, 200, `{"data":{"asns":[{"asn":64500,"holder":"X"}]}}`)
	})
	logs := &logBuffer{}
	missing := filepath.Join(t.TempDir(), "none.csv")
	got := newLocator(&http.Client{Timeout: 5 * time.Second}, testLogger(logs), missing, base)(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7")})
	if !reflect.DeepEqual(got, []place{{country: unknownPlace, network: "AS64500 X"}}) {
		t.Fatalf("places = %+v", got)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="the DB-IP country file could not be read, so the alert shows every country as unknown"`) || !strings.Contains(logs.String(), missing) {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestNewLocator_LooksUpAtMostFourAtOnce(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		inFlight int
		most     int
		release  = make(chan struct{})
		once     sync.Once
	)
	base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		if inFlight == ownerLookups {
			once.Do(func() { close(release) })
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(20 * time.Second):
		}
		writeAnswer(t, w, 200, `{"data":{"asns":[{"asn":64500,"holder":"X"}]}}`)
	})
	addrs := make([]netip.Addr, 3*ownerLookups)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	got := newLocator(&http.Client{Timeout: 30 * time.Second}, testLogger(&logBuffer{}), writeCountries(t, testCountries), base)(context.Background(), addrs)
	mu.Lock()
	defer mu.Unlock()
	if most != ownerLookups {
		t.Fatalf("at most %d lookups ran at once, want %d", most, ownerLookups)
	}
	for i, p := range got {
		if p.network != "AS64500 X" {
			t.Fatalf("address %d: %+v", i, p)
		}
	}
}

type panickingTransport struct{}

func (panickingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("boom")
}

func TestNewLocator_ALookupThatPanicsShowsUnknown(t *testing.T) {
	t.Parallel()
	logs := &logBuffer{}
	got := newLocator(&http.Client{Transport: panickingTransport{}}, testLogger(logs), writeCountries(t, testCountries), "http://owner.example.test/data.json")(
		context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7")})
	if !reflect.DeepEqual(got, []place{{country: "NL", network: unknownPlace}}) {
		t.Fatalf("places = %+v", got)
	}
	for _, want := range []string{"level=ERROR", `msg="` + lookupCrashMsg + `"`, "address=192.0.2.7", "panic=boom", "addresses=1 of=1"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("logs = %s, want %q in them", logs.String(), want)
		}
	}
}
