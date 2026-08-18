package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestClassifyLegoErrors covers the plan's "error classification" row: sample ACME problem documents
// map to the rate-limited / transient / permanent classes.
func TestClassifyLegoErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "429 rate limited", err: &legoacme.ProblemDetails{HTTPStatus: 429}, want: ClassRateLimited},
		{name: "rateLimited type", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 403}, want: ClassRateLimited},
		{name: "500 transient", err: &legoacme.ProblemDetails{HTTPStatus: 500}, want: ClassTransient},
		{name: "badCSR permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:badCSR", HTTPStatus: 400}, want: ClassPermanent},
		{name: "malformed permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:malformed", HTTPStatus: 400}, want: ClassPermanent},
		{name: "rejectedIdentifier permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rejectedIdentifier", HTTPStatus: 400}, want: ClassPermanent},
		{name: "unknown problem transient", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:serverInternal", HTTPStatus: 400}, want: ClassTransient},
		{name: "transport error transient", err: errors.New("dial tcp: connection refused"), want: ClassTransient},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ie := classifyLego(tc.err)
			if ie.Class != tc.want {
				t.Fatalf("classifyLego(%v).Class = %q, want %q", tc.err, ie.Class, tc.want)
			}
		})
	}
}

// TestShouldRenewLEMarginFloor covers the LE renewal timing as BUILT (see the Deviations entry "LE ARI
// margin floor"): an LE cert renews at NotAfter − --acme-renew-margin — for a shortlived (~160h) cert
// that is NotBefore+112h, the same uniform ~4.7-day cadence as the fixed non-LE path.
func TestShouldRenewLEMarginFloor(t *testing.T) {
	lc := &legoClient{cfg: LegoConfig{CAID: CALetsEncrypt, UseARI: true,
		RenewMargin: 48 * time.Hour, Shortlived: 160 * time.Hour}}
	issued := time.Unix(1_700_000_000, 0)
	cur := store.CertInfo{CA: CALetsEncrypt, NotBefore: issued, NotAfter: issued.Add(160 * time.Hour)}

	due, at, err := lc.shouldRenew(context.Background(), cur, issued.Add(111*time.Hour))
	if err != nil || due {
		t.Fatalf("before NotAfter−margin the cert must not be due (due=%v err=%v)", due, err)
	}
	if want := issued.Add(112 * time.Hour); !at.Equal(want) {
		t.Fatalf("renew-at = %s, want NotAfter−margin = %s", at, want)
	}
	if due, _, _ := lc.shouldRenew(context.Background(), cur, issued.Add(113*time.Hour)); !due {
		t.Fatal("past NotAfter−margin the cert must be due")
	}
}

// TestClassifyRateLimitedErrorHonorsRetryAfter: lego's *acme.RateLimitedError carries the CA's
// literal Retry-After header — classification must parse and honor it (and fall back to 0 → the
// cooldown default when the header is absent or unparsable).
func TestClassifyRateLimitedErrorHonorsRetryAfter(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		want time.Duration
	}{
		{name: "seconds form", hdr: "120", want: 2 * time.Minute},
		{name: "absent header", hdr: "", want: 0},
		{name: "garbage header", hdr: "not-a-time", want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &legoacme.RateLimitedError{
				ProblemDetails: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 429},
				RetryAfter:     tc.hdr,
			}
			ie := classifyLego(err)
			if ie.Class != ClassRateLimited {
				t.Fatalf("class = %q, want rate-limited", ie.Class)
			}
			if ie.Retry != tc.want {
				t.Fatalf("Retry = %s, want %s", ie.Retry, tc.want)
			}
		})
	}
}
