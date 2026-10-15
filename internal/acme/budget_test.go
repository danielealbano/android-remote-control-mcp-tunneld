package acme

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

func keys(bs []limit.Bucket) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.Key)
	}
	return out
}

func TestRegisteredDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "a.b.example.com", want: "example.com"},
		{in: "x.example.co.uk", want: "example.co.uk"},
		{in: "Name.Example.COM.", want: "example.com"},
		{in: "co.uk", want: "co.uk"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := registeredDomain(tc.in); got != tc.want {
				t.Fatalf("registeredDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOrderBuckets_PerCAAndPath(t *testing.T) {
	b := testBudgets()
	le := &account{ca: CALetsEncrypt, id: "le-1"}
	gts := &account{ca: CAGTS, id: "gts-1"}
	zs := &account{ca: CAZeroSSL, id: "zs-1"}
	tests := []struct {
		name                 string
		acct                 *account
		renewal              bool
		wantCreate, wantSucc []string
	}{
		{name: "le new name", acct: le, wantCreate: []string{"letsencrypt:orders:le-1"},
			wantSucc: []string{"letsencrypt:name:p.t.example.com", "letsencrypt:domain:example.com"}},
		{name: "le renewal", acct: le, renewal: true, wantSucc: []string{"letsencrypt:name:p.t.example.com"}},
		{name: "gts", acct: gts, wantCreate: []string{"gts:orders:gts-1"}},
		{name: "zerossl", acct: zs, wantCreate: []string{"zerossl:orders:zs-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			create, succ := b.orderBuckets(tc.acct, "p.t.example.com", tc.renewal)
			if !slices.Equal(keys(create), tc.wantCreate) || !slices.Equal(keys(succ), tc.wantSucc) {
				t.Fatalf("orderBuckets = %v / %v, want %v / %v", keys(create), keys(succ), tc.wantCreate, tc.wantSucc)
			}
		})
	}
}

func TestRequestBuckets_GTSCertURL(t *testing.T) {
	b := testBudgets()
	req := func(path string) *http.Request { return &http.Request{URL: &url.URL{Path: path}} }
	tests := []struct {
		name string
		acct *account
		path string
		want []string
	}{
		{name: "gts cert poll", acct: &account{ca: CAGTS, id: "g"}, path: "/cert/x", want: []string{"gts:requests:g", "gts:cert:g"}},
		{name: "gts other", acct: &account{ca: CAGTS, id: "g"}, path: "/order/x", want: []string{"gts:requests:g"}},
		{name: "zerossl", acct: &account{ca: CAZeroSSL, id: "z"}, path: "/cert/x", want: []string{"zerossl:requests:z"}},
		{name: "le", acct: &account{ca: CALetsEncrypt, id: "l"}, path: "/cert/x", want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := keys(b.requestBuckets(tc.acct, req(tc.path))); !slices.Equal(got, tc.want) {
				t.Fatalf("requestBuckets = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResyncBuckets_NamedLimit(t *testing.T) {
	b := testBudgets()
	le := &account{ca: CALetsEncrypt, id: "l"}
	tr := newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com"))
	tests := []struct {
		name   string
		acct   *account
		detail string
		tr     *orderTrack
		want   []string
	}{
		{name: "le domain", acct: le, tr: tr, detail: "too many certificates: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-registered-domain",
			want: []string{"letsencrypt:domain:example.com"}},
		{name: "le orders", acct: le, tr: tr, detail: "see #new-orders-per-account", want: []string{"letsencrypt:orders:l"}},
		{name: "le name", acct: le, tr: tr, detail: "see #new-certificates-per-exact-set-of-identifiers", want: []string{"letsencrypt:name:p.example.com"}},
		{name: "le orders without tracker", acct: le, detail: "see #new-orders-per-account", want: []string{"letsencrypt:orders:l"}},
		{name: "le domain without tracker", acct: le, detail: "see #new-certificates-per-registered-domain", want: []string{}},
		{name: "le unknown detail", acct: le, tr: tr, detail: "something else", want: []string{}},
		{name: "gts cert", acct: &account{ca: CAGTS, id: "g"}, detail: `over quota (50 requests in 60 seconds) for the given ACME resource "cert"`, want: []string{"gts:cert:g"}},
		{name: "gts order", acct: &account{ca: CAGTS, id: "g"}, detail: `over quota (250 requests in 60 seconds) for the given ACME resource "order"`, want: []string{"gts:requests:g"}},
		{name: "gts other", acct: &account{ca: CAGTS, id: "g"}, detail: "", want: []string{"gts:requests:g"}},
		{name: "zerossl", acct: &account{ca: CAZeroSSL, id: "z"}, detail: "", want: []string{"zerossl:requests:z"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := keys(b.resyncBuckets(tc.acct, tc.detail, tc.tr)); !slices.Equal(got, tc.want) {
				t.Fatalf("resyncBuckets = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrderTrack_PollDueAndCleanups(t *testing.T) {
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	t0 := time.Unix(1_700_000_000, 0)
	tr.setOrder("https://ca/order/1", "https://ca/finalize/1")
	if tr.isPoll("https://ca/order/1") {
		t.Fatal("a request before finalize is not a certificate poll")
	}
	tr.markFinalized(t0)
	if !tr.isPoll("https://ca/order/1") || !tr.isFinalize("https://ca/finalize/1") {
		t.Fatal("after finalize the order URL is a poll and the finalize URL is recognised")
	}
	if got := tr.pollDue(5*time.Second, 2*time.Second); !got.Equal(t0.Add(5 * time.Second)) {
		t.Fatalf("first poll due %s, want finalize + 5 s", got)
	}
	tr.markPoll(t0.Add(6 * time.Second))
	if got := tr.pollDue(5*time.Second, 2*time.Second); !got.Equal(t0.Add(8 * time.Second)) {
		t.Fatalf("next poll due %s, want last poll + 2 s", got)
	}
	var ran int
	tr.onAbandon(func(context.Context) error { ran++; return nil })
	if fs := tr.takeCleanups(); len(fs) != 1 {
		t.Fatalf("takeCleanups returned %d, want 1", len(fs))
	}
	if fs := tr.takeCleanups(); len(fs) != 0 {
		t.Fatal("cleanups are handed out once")
	}
	if ran != 0 {
		t.Fatal("takeCleanups must not run them")
	}
}

type fakeTLSALPN struct {
	put, deleted []string
}

func (f *fakeTLSALPN) PutTLSALPN(_ context.Context, domain, keyAuth string) error {
	f.put = append(f.put, domain+"/"+keyAuth)
	return nil
}

func (f *fakeTLSALPN) DeleteTLSALPN(_ context.Context, domain, keyAuth string) error {
	f.deleted = append(f.deleted, domain+"/"+keyAuth)
	return nil
}

func TestTLSALPNPresent_RegistersCleanup(t *testing.T) {
	store := &fakeTLSALPN{}
	p := &tlsALPNProvider{s: store}
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	if err := p.Present(withTrack(context.Background(), tr), "n.example.test", "", "ka"); err != nil {
		t.Fatal(err)
	}
	cleanups := tr.takeCleanups()
	if len(cleanups) != 1 {
		t.Fatalf("Present with a tracker registered %d cleanups, want 1", len(cleanups))
	}
	if err := cleanups[0](context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(store.deleted, []string{"n.example.test/ka"}) {
		t.Fatalf("the cleanup deleted %v, want the presented challenge", store.deleted)
	}
	if err := p.Present(context.Background(), "m.example.test", "", "kb"); err != nil {
		t.Fatal(err)
	}
	if len(store.put) != 2 || len(store.deleted) != 1 {
		t.Fatalf("a Present without a tracker stores the challenge and registers no cleanup: put %v deleted %v", store.put, store.deleted)
	}
}
