package acme

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

type Budgets struct {
	Domain          string
	LEDomain        limit.Rate
	LEOrders        limit.Rate
	LEName          limit.Rate
	GTSOrders       limit.Rate
	GTSRequests     limit.Rate
	GTSCertPolls    limit.Rate
	ZeroSSLOrders   limit.Rate
	ZeroSSLRequests limit.Rate
}

type NodeLister interface {
	LiveNodeIDs(ctx context.Context) ([]string, error)
}

type BudgetLevel struct {
	CA      string
	Account string
	Budget  string
	Ratio   float64
}

type account struct {
	ca      string
	id      string
	label   string
	timeout time.Duration
	issuer  caIssuer
}

type namedBucket struct {
	name string
	b    limit.Bucket
}

func registeredDomain(fqdn string) string {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	d, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name
	}
	return d
}

func (b Budgets) leDomain(fqdn string) limit.Bucket {
	return b.LEDomain.Bucket("letsencrypt:domain:" + registeredDomain(fqdn))
}
func (b Budgets) leOrders(a *account) limit.Bucket {
	return b.LEOrders.Bucket("letsencrypt:orders:" + a.id)
}
func (b Budgets) leName(fqdn string) limit.Bucket { return b.LEName.Bucket("letsencrypt:name:" + fqdn) }
func (b Budgets) gtsOrders(a *account) limit.Bucket { return b.GTSOrders.Bucket("gts:orders:" + a.id) }
func (b Budgets) gtsRequests(a *account) limit.Bucket {
	return b.GTSRequests.Bucket("gts:requests:" + a.id)
}
func (b Budgets) gtsCertPolls(a *account) limit.Bucket { return b.GTSCertPolls.Bucket("gts:cert:" + a.id) }
func (b Budgets) zerosslOrders(a *account) limit.Bucket {
	return b.ZeroSSLOrders.Bucket("zerossl:orders:" + a.id)
}
func (b Budgets) zerosslRequests(a *account) limit.Bucket {
	return b.ZeroSSLRequests.Bucket("zerossl:requests:" + a.id)
}

func (b Budgets) orderBuckets(a *account, fqdn string, leRenewal bool) (onCreate, onSuccess []limit.Bucket) {
	switch a.ca {
	case CALetsEncrypt:
		if leRenewal {
			return nil, []limit.Bucket{b.leName(fqdn)}
		}
		return []limit.Bucket{b.leOrders(a)}, []limit.Bucket{b.leName(fqdn), b.leDomain(fqdn)}
	case CAGTS:
		return []limit.Bucket{b.gtsOrders(a)}, nil
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslOrders(a)}, nil
	}
	return nil, nil
}

func (b Budgets) requestBuckets(a *account, req *http.Request) []limit.Bucket {
	switch a.ca {
	case CAGTS:
		if strings.Contains(req.URL.Path, "/cert/") {
			return []limit.Bucket{b.gtsRequests(a), b.gtsCertPolls(a)}
		}
		return []limit.Bucket{b.gtsRequests(a)}
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslRequests(a)}
	}
	return nil
}

func (b Budgets) resyncBuckets(a *account, detail string, tr *orderTrack) []limit.Bucket {
	switch a.ca {
	case CALetsEncrypt:
		switch {
		case strings.Contains(detail, "#new-orders-per-account"):
			return []limit.Bucket{b.leOrders(a)}
		case tr == nil:
			return nil
		case strings.Contains(detail, "#new-certificates-per-registered-domain") && tr.domain.Key != "":
			return []limit.Bucket{tr.domain}
		case strings.Contains(detail, "#new-certificates-per-exact-set-of-identifiers") && tr.name.Key != "":
			return []limit.Bucket{tr.name}
		}
		return nil
	case CAGTS:
		if strings.Contains(detail, `resource "cert"`) {
			return []limit.Bucket{b.gtsCertPolls(a)}
		}
		return []limit.Bucket{b.gtsRequests(a)}
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslRequests(a)}
	}
	return nil
}

func (b Budgets) accountBuckets(a *account) []namedBucket {
	switch a.ca {
	case CALetsEncrypt:
		return []namedBucket{{"domain", b.leDomain(b.Domain)}, {"orders", b.leOrders(a)}}
	case CAGTS:
		return []namedBucket{{"orders", b.gtsOrders(a)}, {"requests", b.gtsRequests(a)}, {"cert-polls", b.gtsCertPolls(a)}}
	case CAZeroSSL:
		return []namedBucket{{"orders", b.zerosslOrders(a)}, {"requests", b.zerosslRequests(a)}}
	}
	return nil
}

func (b Budgets) ordersBucket(a *account) limit.Bucket {
	switch a.ca {
	case CAGTS:
		return b.gtsOrders(a)
	case CAZeroSSL:
		return b.zerosslOrders(a)
	}
	return b.leOrders(a)
}
