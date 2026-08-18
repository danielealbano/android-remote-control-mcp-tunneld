package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestE2EFamiliesExportedNoTunnelLabels(t *testing.T) {
	m := NewMetrics()
	rec := NewPromRecorder(m, nil, nil, nil)

	rec.PublicConnOpen()
	rec.PhoneConnOpen()
	rec.StreamOpen()
	rec.AttestVerify("ok")
	rec.ACMEIssue("letsencrypt", "ok")
	rec.ACMERenew("gts", "ok")
	rec.QuotaExhausted("secret-tunnel-name", "day")
	rec.ACMECooldown("zerossl")
	rec.MeshPool("10.0.0.1:9443", 4)

	got, err := testutil.GatherAndCount(m.Registry(),
		"tunneld_public_connections", "tunneld_phone_connections", "tunneld_streams_active",
		"tunneld_attest_verify_total", "tunneld_acme_issue_total", "tunneld_acme_renew_total",
		"tunneld_quota_exhausted_total", "tunneld_acme_cooldown_total", "tunneld_mesh_pool_size")
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Error("E2E families should be exported after recording")
	}

	// No metric family carries a tunnel-name label (cardinality): the quota tunnel name must NOT leak.
	mfs, _ := m.Registry().Gather()
	for _, mf := range mfs {
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if strings.Contains(lp.GetValue(), "secret-tunnel-name") {
					t.Errorf("tunnel name leaked into metric labels: %s", mf.GetName())
				}
			}
		}
	}
}
