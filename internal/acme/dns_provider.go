package acme

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

// DNSProviderByName resolves a lego-native DNS-01 provider from its id (the --acme-dns-provider flag,
// e.g. "cloudflare", "route53"). The provider reads its own credentials from the environment per lego's
// conventions. Importing lego's provider registry pulls the full provider set into the binary — the
// intentional cost of honoring an arbitrary provider id (see the plan's Deviations).
func DNSProviderByName(name string) (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(name)
}
