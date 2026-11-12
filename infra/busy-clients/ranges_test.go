package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testPage = `<html><h1>IP addresses</h1><p><code>aws-external-anthropic.example.test</code></p>` +
	`<h2 id="inbound-ip-addresses">Inbound IP addresses</h2><p><code>203.0.113.0/24</code></p>` +
	`<h2 id="outbound-ip-addresses">Outbound IP addresses</h2><h3>IPv4</h3><p><code>192.0.2.128/25</code></p>` +
	`<pre><code>198.51.100.0/26 198.51.100.64/26</code></pre><p><code>not-a-range.example.test</code></p>` +
	`<h3>IPv6</h3><p><code>2001:db8:1::1/48</code></p>` +
	`<h3 id="phased-out-ip-addresses">Phased out IP addresses</h3><pre><code>203.0.113.9/32</code></pre></html>`

func rangeServer(t *testing.T, bodies map[string]string, codes map[string]int) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, ok := codes[r.URL.Path]; ok {
			w.WriteHeader(code)
		}
		if _, err := w.Write([]byte(bodies[r.URL.Path])); err != nil {
			t.Errorf("write %s: %v", r.URL.Path, err)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestLoadRanges_ReadsBothSources(t *testing.T) {
	t.Parallel()
	base := rangeServer(t, map[string]string{
		"/connectors.json": `{"creationTime":"2026-11-12T00:00:00","prefixes":[{"ipv4Prefix":"192.0.2.5/24"},{"ipv6Prefix":"2001:db8::/32"}]}`,
		"/user.json":       `{"prefixes":[{"ipv4Prefix":"198.51.100.7/32"}]}`,
		"/page":            testPage,
	}, nil)
	got, err := loadRanges(context.Background(), &http.Client{Timeout: 5 * time.Second}, []string{base + "/connectors.json", base + "/user.json"}, base+"/page")
	if err != nil {
		t.Fatal(err)
	}
	var want []netip.Prefix
	for _, p := range []string{"192.0.2.0/24", "2001:db8::/32", "198.51.100.7/32", "192.0.2.128/25", "198.51.100.0/26", "198.51.100.64/26", "2001:db8:1::/48"} {
		want = append(want, netip.MustParsePrefix(p))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ranges = %v\nwant     %v", got, want)
	}
}

func TestLoadRanges_Failures(t *testing.T) {
	t.Parallel()
	goodList := `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`
	outbound := `<h2 id="outbound-ip-addresses">Outbound</h2><p><code>192.0.2.128/25</code></p>`
	phasedOut := `<h3 id="phased-out-ip-addresses">Phased out</h3>`
	tests := []struct {
		name      string
		list      string
		listCode  int
		page      string
		noOpenAI  bool
		noPage    bool
		closed    bool
		wantErr   string
		wantNamed string
	}{
		{name: "no OpenAI list", noOpenAI: true, page: testPage, wantErr: "no OpenAI address list is set"},
		{name: "no Anthropic page", list: goodList, noPage: true, wantErr: "the Anthropic address page is not set"},
		{name: "a list that does not answer 200", list: goodList, listCode: http.StatusInternalServerError, page: testPage, wantErr: "status 500", wantNamed: "/list.json"},
		{name: "a list that is not JSON", list: "<html>", page: testPage, wantErr: "decode the OpenAI address list", wantNamed: "/list.json"},
		{name: "a list entry that is not a range", list: `{"prefixes":[{"ipv4Prefix":"999.1.1.1/8"}]}`, page: testPage, wantErr: `read the range "999.1.1.1/8"`, wantNamed: "/list.json"},
		{name: "a list without range", list: `{"prefixes":[]}`, page: testPage, wantErr: "has no range", wantNamed: "/list.json"},
		{name: "a page without the outbound heading", list: goodList, page: phasedOut, wantErr: "has no outbound section followed by the phased-out one", wantNamed: "/page"},
		{name: "a page without the phased-out heading", list: goodList, page: outbound, wantErr: "has no outbound section followed by the phased-out one", wantNamed: "/page"},
		{name: "the headings in the wrong order", list: goodList, page: phasedOut + outbound, wantErr: "has no outbound section followed by the phased-out one", wantNamed: "/page"},
		{name: "an outbound section without range", list: goodList, page: `<h2 id="outbound-ip-addresses">Outbound</h2><p><code>example.test</code></p>` + phasedOut, wantErr: "the outbound section of the Anthropic address page", wantNamed: "/page"},
		{name: "a page over 4 MiB", list: goodList, page: testPage + strings.Repeat("x", maxRangeBytes), wantErr: "larger than", wantNamed: "/page"},
		{name: "a server that does not answer", closed: true, wantErr: "fetch", wantNamed: "/list.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			codes := map[string]int{}
			if tc.listCode != 0 {
				codes["/list.json"] = tc.listCode
			}
			base := rangeServer(t, map[string]string{"/list.json": tc.list, "/page": tc.page}, codes)
			if tc.closed {
				ts := httptest.NewServer(http.NotFoundHandler())
				ts.Close()
				base = ts.URL
			}
			openAI := []string{base + "/list.json"}
			if tc.noOpenAI {
				openAI = nil
			}
			page := base + "/page"
			if tc.noPage {
				page = ""
			}
			_, err := loadRanges(context.Background(), &http.Client{Timeout: 5 * time.Second}, openAI, page)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), tc.wantNamed) {
				t.Fatalf("err = %v, want one containing %q and %q", err, tc.wantErr, tc.wantNamed)
			}
		})
	}
}
