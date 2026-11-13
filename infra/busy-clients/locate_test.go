package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	"198.51.100.0,198.51.100.127,YY\n" +
	" 192.0.2.0 , 192.0.2.255 , xx \n" +
	"203.0.113.0,203.0.113.9\n" +
	"2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,YY\n" +
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

func TestCountriesOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "the first address of a padded, lower-case row", addr: "192.0.2.0", want: "XX"},
		{name: "the last address of a range", addr: "192.0.2.255", want: "XX"},
		{name: "a range listed before a lower one", addr: "198.51.100.7", want: "YY"},
		{name: "a gap between ranges", addr: "198.51.100.200", want: ""},
		{name: "before the first range", addr: "10.0.0.1", want: ""},
		{name: "a row with two fields is skipped", addr: "203.0.113.5", want: ""},
		{name: "an IPv6 address", addr: "2001:db8:1:2::5", want: "YY"},
		{name: "an IPv6 address before any IPv6 range", addr: "::1", want: ""},
	}
	path := writeCountries(t, testCountries)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := netip.MustParseAddr(tc.addr)
			got, err := countriesOf(path, []netip.Addr{a, a})
			if err != nil {
				t.Fatal(err)
			}
			if code, ok := got[a]; code != tc.want || ok != (tc.want != "") {
				t.Fatalf("countriesOf(%s) = %q (found %v), want %q", tc.addr, code, ok, tc.want)
			}
		})
	}
}

func TestCountriesOf_Failures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string
	}{
		{name: "a missing file", path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.csv") }, wantErr: "open the DB-IP country file"},
		{name: "a file without a valid row", path: func(t *testing.T) string { return writeCountries(t, "a,b,c\n1.2.3,x,y\n") }, wantErr: "has no valid row"},
		{name: "a path that cannot be read", path: func(t *testing.T) string { return t.TempDir() }, wantErr: "read the DB-IP country file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := countriesOf(tc.path(t), []netip.Addr{netip.MustParseAddr("192.0.2.7")}); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestOwnerEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "an https address", raw: "https://stat.example.test/data/prefix-overview/data.json"},
		{name: "an http address", raw: "http://127.0.0.1:8080/data.json"},
		{name: "an empty address", raw: "", wantErr: true},
		{name: "no scheme", raw: "stat.example.test/data.json", wantErr: true},
		{name: "another scheme", raw: "ftp://stat.example.test/data.json", wantErr: true},
		{name: "no host", raw: "https:///data.json", wantErr: true},
		{name: "an address that does not parse", raw: "http://[::1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ownerEndpoint(tc.raw); (err != nil) != tc.wantErr {
				t.Fatalf("ownerEndpoint(%q) = %v, want an error: %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func ownerServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *url.URL {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(answer))
	t.Cleanup(ts.Close)
	u, err := ownerEndpoint(ts.URL + "/data/prefix-overview/data.json?data_overload_limit=ignore")
	if err != nil {
		t.Fatal(err)
	}
	return u
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
		{name: "one network", code: 200, body: `{"status":"ok","data":{"announced":true,"asns":[{"asn":64500,"holder":"EXAMPLE Example GmbH"}]}}`, want: "AS64500 EXAMPLE Example GmbH"},
		{name: "two networks", code: 200, body: `{"status":"ok","data":{"announced":true,"asns":[{"asn":64500,"holder":"A"},{"asn":64501,"holder":"B"}]}}`, want: "AS64500 A, AS64501 B"},
		{name: "an address nobody announces", code: 200, body: `{"status":"ok","data":{"announced":false,"asns":[]}}`, want: "not announced"},
		{name: "announced without a network", code: 200, body: `{"status":"ok","data":{"announced":true,"asns":[]}}`, want: "not announced"},
		{name: "control characters are replaced", code: 200, body: `{"status":"ok","data":{"announced":true,"asns":[{"asn":64500,"holder":"A\u202eB"}]}}`, want: "AS64500 A\uFFFDB"},
		{name: "a long name is clipped", code: 200, body: `{"status":"ok","data":{"announced":true,"asns":[{"asn":64500,"holder":"` + long + `"}]}}`, want: ("AS64500 " + long)[:ownerRunes] + "…"},
		{name: "a status that is not ok", code: 200, body: `{"status":"maintenance","data":{}}`, wantErr: `answered with status "maintenance"`},
		{name: "an answer without the announced field", code: 200, body: `{"status":"ok","data":{"asns":[]}}`, wantErr: "did not say whether the address is announced"},
		{name: "an answer that is not 200", code: 503, body: "busy", wantErr: "status 503"},
		{name: "an answer that is not JSON", code: 200, body: "<html>", wantErr: "decode the network owner of 192.0.2.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu    sync.Mutex
				query url.Values
			)
			base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				query = r.URL.Query()
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
			if err != nil || got != tc.want {
				t.Fatalf("lookupOwner = %q, %v; want %q", got, err, tc.want)
			}
			want := url.Values{"resource": {"192.0.2.7"}, "sourceapp": {"arc-busy-clients"}, "data_overload_limit": {"ignore"}}
			if !reflect.DeepEqual(query, want) {
				t.Fatalf("query = %v, want %v", query, want)
			}
		})
	}
}

func TestLookupBudget(t *testing.T) {
	t.Parallel()
	far, cancelFar := context.WithTimeout(context.Background(), time.Hour)
	defer cancelFar()
	near, cancelNear := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelNear()
	tests := []struct {
		name string
		ctx  context.Context
		max  time.Duration
		min  time.Duration
	}{
		{name: "a run without a deadline gets the whole budget", ctx: context.Background(), min: ownerBudget, max: ownerBudget},
		{name: "a run with plenty of time gets the whole budget", ctx: far, min: ownerBudget, max: ownerBudget},
		{name: "a run near its deadline gets half the time left", ctx: near, min: 4 * time.Second, max: 5 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := lookupBudget(tc.ctx, ownerBudget); got < tc.min || got > tc.max {
				t.Fatalf("lookupBudget = %s, want between %s and %s", got, tc.min, tc.max)
			}
		})
	}
}

func okOwner(t *testing.T, w http.ResponseWriter, holder string) {
	t.Helper()
	writeAnswer(t, w, 200, `{"status":"ok","data":{"announced":true,"asns":[{"asn":64500,"holder":"`+holder+`"}]}}`)
}

func TestNewLocator_GivesCountriesAndOwners(t *testing.T) {
	t.Parallel()
	base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("resource") {
		case "198.51.100.7":
			writeAnswer(t, w, 500, "broken")
		default:
			okOwner(t, w, "Owner of "+r.URL.Query().Get("resource"))
		}
	})
	logs := &logBuffer{}
	locate := newLocator(&http.Client{Timeout: 5 * time.Second}, testLogger(logs), writeCountries(t, testCountries), base, ownerBudget)
	got := locate(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.5")})
	want := []place{
		{country: "XX", network: "AS64500 Owner of 192.0.2.7"},
		{country: "YY", network: unknownPlace},
		{country: unknownPlace, network: "AS64500 Owner of 203.0.113.5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("places = %+v\nwant     %+v", got, want)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="the network owner of an address could not be looked up, so it shows as unknown" address=198.51.100.7`) ||
		!strings.Contains(logs.String(), "status 500") || strings.Contains(logs.String(), "ran out") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestNewLocator_WithoutTheCountryFileShowsUnknownCountries(t *testing.T) {
	t.Parallel()
	base := ownerServer(t, func(w http.ResponseWriter, _ *http.Request) { okOwner(t, w, "X") })
	logs := &logBuffer{}
	missing := filepath.Join(t.TempDir(), "none.csv")
	got := newLocator(&http.Client{Timeout: 5 * time.Second}, testLogger(logs), missing, base, ownerBudget)(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7")})
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
		reached  = make(chan struct{})
		release  = make(chan struct{})
		once     sync.Once
	)
	base := ownerServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		if inFlight == ownerLookups {
			once.Do(func() { close(reached) })
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
		}
		okOwner(t, w, "X")
	})
	addrs := make([]netip.Addr, 3*ownerLookups)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	done := make(chan []place, 1)
	go func() {
		done <- newLocator(&http.Client{Timeout: 30 * time.Second}, testLogger(&logBuffer{}), writeCountries(t, testCountries), base, ownerBudget)(context.Background(), addrs)
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("fewer than four lookups ever ran at once")
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	held := most
	mu.Unlock()
	close(release)
	got := <-done
	if held != ownerLookups {
		t.Fatalf("%d lookups ran at once while four were held, want %d", held, ownerLookups)
	}
	for i, p := range got {
		if p.network != "AS64500 X" {
			t.Fatalf("address %d: %+v", i, p)
		}
	}
}

func TestNewLocator_TheBudgetEndsTheLookups(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		requests int
	)
	base := ownerServer(t, func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		<-r.Context().Done()
	})
	addrs := make([]netip.Addr, 2*ownerLookups)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	logs := &logBuffer{}
	got := newLocator(&http.Client{Timeout: 30 * time.Second}, testLogger(logs), writeCountries(t, testCountries), base, 100*time.Millisecond)(context.Background(), addrs)
	for i, p := range got {
		if p.network != unknownPlace || p.country != "XX" {
			t.Fatalf("address %d: %+v", i, p)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if requests > ownerLookups {
		t.Fatalf("%d requests were sent, want at most %d: lookups still waiting when the time ran out must send nothing", requests, ownerLookups)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="the time for the network owner lookups ran out, so some addresses show their owner as unknown" addresses=8 of=8`) ||
		strings.Contains(logs.String(), "could not be looked up") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestNewLocator_LeavesHalfTheRunForSending(t *testing.T) {
	t.Parallel()
	base := ownerServer(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	newLocator(&http.Client{Timeout: 30 * time.Second}, testLogger(&logBuffer{}), writeCountries(t, testCountries), base, ownerBudget)(
		ctx, []netip.Addr{netip.MustParseAddr("192.0.2.7")})
	deadline, _ := ctx.Deadline()
	if left := time.Until(deadline); left < 800*time.Millisecond {
		t.Fatalf("the lookups left only %s of the run, want about half of it", left)
	}
}

type panickingTransport struct{}

func (panickingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("boom")
}

func TestNewLocator_ALookupThatPanicsShowsUnknown(t *testing.T) {
	t.Parallel()
	logs := &logBuffer{}
	owners, err := ownerEndpoint("http://owner.example.test/data.json")
	if err != nil {
		t.Fatal(err)
	}
	got := newLocator(&http.Client{Transport: panickingTransport{}}, testLogger(logs), writeCountries(t, testCountries), owners, ownerBudget)(
		context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.7")})
	if !reflect.DeepEqual(got, []place{{country: "XX", network: unknownPlace}}) {
		t.Fatalf("places = %+v", got)
	}
	for _, want := range []string{"level=ERROR", `msg="` + lookupCrashMsg + `"`, "address=192.0.2.7", "panic=boom", "looking up the network owner of 192.0.2.7 crashed"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("logs = %s, want %q in them", logs.String(), want)
		}
	}
}
