package metrics

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

// registeredFamilies exercises every recorder event once and returns the set of tunneld_* metric
// family names actually registered (stripping the _sum/_count/_bucket/_total-less variants Prometheus
// emits), so the deploy artifacts can be checked against the REAL families.
func registeredFamilies(t *testing.T) map[string]struct{} {
	t.Helper()
	m := NewMetrics()
	rec := NewPromRecorder(m, nil, nil, nil)
	rec.Reject("ban", "x", "1.1.1.1")
	rec.Bytes("x", "in", 1)
	rec.EnrollmentResult("ok")
	rec.AttestVerify("ok")
	rec.ACMEIssue("letsencrypt", "ok")
	rec.ACMERenew("letsencrypt", "ok")
	rec.ACMECooldown("letsencrypt")
	rec.QuotaExhausted("x", "day")
	rec.MeshPool("10.0.0.2:9443", 4)
	rec.PublicConnOpen()
	rec.PhoneConnOpen()
	rec.StreamOpen()

	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]struct{}{}
	for _, f := range fams {
		set[f.GetName()] = struct{}{}
	}
	return set
}

// TestGrafanaDashboardReferencesRealFamilies fails if the shipped dashboard queries any tunneld_*
// family that is not actually registered — the class of stale-artifact drift where a removed metric
// family leaves the dashboard querying a name that no longer exists (permanently empty panels).
func TestGrafanaDashboardReferencesRealFamilies(t *testing.T) {
	data, err := os.ReadFile("../../deploy/grafana/provisioning/dashboards/tunneld.json")
	if err != nil {
		t.Fatal(err)
	}
	registered := registeredFamilies(t)
	re := regexp.MustCompile(`tunneld_[a-z_]+`)
	for _, ref := range dedup(re.FindAllString(string(data), -1)) {
		// Histogram/summary suffixes would be stripped, but the E2E families are counters/gauges only.
		if _, ok := registered[ref]; !ok {
			t.Errorf("dashboard references unregistered metric family %q", ref)
		}
	}
}

// TestPrometheusAlertsReferenceRealReasons fails if any alert rule matches a tunneld_rejections_total
// reason label that is not in observ.RejectReasons — the class of dead-alert drift where an alert rule
// matches a rejection label PromRecorder.Reject refuses, so the alert can never fire.
func TestPrometheusAlertsReferenceRealReasons(t *testing.T) {
	data, err := os.ReadFile("../../deploy/prometheus/alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]struct{}{}
	for _, r := range observ.RejectReasons {
		known[r] = struct{}{}
	}
	// Match reason="literal" and reason=~"a|b|c" (regex alternations, incl. attest-.* prefixes).
	reEq := regexp.MustCompile(`reason="([^"]+)"`)
	reRe := regexp.MustCompile(`reason=~"([^"]+)"`)
	body := string(data)
	for _, m := range reEq.FindAllStringSubmatch(body, -1) {
		if _, ok := known[m[1]]; !ok {
			t.Errorf("alert matches unknown rejection reason %q", m[1])
		}
	}
	for _, m := range reRe.FindAllStringSubmatch(body, -1) {
		for _, alt := range strings.Split(m[1], "|") {
			if !matchesAnyReason(alt, known) {
				t.Errorf("alert regex alternative %q matches no observ.RejectReasons label", alt)
			}
		}
	}
}

// matchesAnyReason reports whether a PromQL label-regex alternative matches at least one known reason
// (supporting the `.*` suffix wildcard used for the attest-* family).
func matchesAnyReason(alt string, known map[string]struct{}) bool {
	if _, ok := known[alt]; ok {
		return true
	}
	if strings.HasSuffix(alt, ".*") {
		prefix := strings.TrimSuffix(alt, ".*")
		for r := range known {
			if strings.HasPrefix(r, prefix) {
				return true
			}
		}
	}
	return false
}

func dedup(ss []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
