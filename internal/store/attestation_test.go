package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestAttestationKey_LayoutSortsByTime(t *testing.T) {
	t.Parallel()
	early := store.AttestationKey("abc", store.Attestation{TS: time.Date(2026, 8, 17, 1, 2, 3, 4, time.UTC)})
	late := store.AttestationKey("abc", store.Attestation{TS: time.Date(2026, 11, 25, 9, 0, 0, 0, time.FixedZone("x", 3600))})
	for _, k := range []string{early, late} {
		if !strings.HasPrefix(k, "attestations/abc/") || !strings.HasSuffix(k, ".json") {
			t.Errorf("AttestationKey layout wrong: %q", k)
		}
	}
	if !strings.HasPrefix(early, "attestations/abc/20260817T010203.000000004Z-") {
		t.Errorf("AttestationKey must carry the UTC nanosecond timestamp: %q", early)
	}
	if early >= late {
		t.Errorf("keys must sort by time: %q !< %q", early, late)
	}
}

func TestDeviceInfo_JSONStaysCompatible(t *testing.T) {
	t.Parallel()
	old := `{"os_version":150000,"os_patch":202602,"vendor_patch":20260201,"boot_patch":20260201,"attestation_version":300,"keymint_version":300,"security_level":"tee"}`
	var got store.DeviceInfo
	if err := json.Unmarshal([]byte(old), &got); err != nil {
		t.Fatalf("a record written before the device properties must still decode: %v", err)
	}
	want := store.DeviceInfo{OSVersion: 150000, OSPatch: 202602, VendorPatch: 20260201, BootPatch: 20260201, AttestationVersion: 300, KeymintVersion: 300, SecurityLevel: "tee"}
	if got != want {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != old {
		t.Errorf("a record without device properties must keep its JSON shape:\n got %s\nwant %s", b, old)
	}
	got.Model, got.Brand = "model-x", "brand-x"
	b, err = json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"brand":"brand-x"`) || !strings.Contains(string(b), `"model":"model-x"`) || strings.Contains(string(b), `"device":`) {
		t.Errorf("only the attested device properties are written: %s", b)
	}
	got.VerifiedBootKey, got.VerifiedBootHash = "0102", "0304"
	b, err = json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"verified_boot_key":"0102"`) || !strings.Contains(string(b), `"verified_boot_hash":"0304"`) {
		t.Errorf("the verified boot key and hash must be written: %s", b)
	}
}

func TestReportedDevice_WrittenOnlyWhenSet(t *testing.T) {
	t.Parallel()
	reported := store.ReportedDevice{Model: "model-r", Fingerprint: "brand/product/device:16/ID/1:user/release-keys"}
	tests := []struct {
		name  string
		empty any
		set   any
	}{
		{name: "name record", empty: store.NameRecord{}, set: store.NameRecord{ReportedDevice: reported}},
		{name: "attestation", empty: store.Attestation{}, set: store.Attestation{ReportedDevice: reported}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tc.empty)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "reported_device") {
				t.Errorf("nothing reported must keep the old JSON shape: %s", b)
			}
			b, err = json.Marshal(tc.set)
			if err != nil {
				t.Fatal(err)
			}
			want := `"reported_device":{"model":"model-r","fingerprint":"brand/product/device:16/ID/1:user/release-keys"}`
			if !strings.Contains(string(b), want) {
				t.Errorf("JSON = %s, want it to contain %s", b, want)
			}
		})
	}
}

func TestFakeAttestations_PruneKeepsTheNewest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := tunneltest.NewStore()
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := range 12 {
		if err := s.PutAttestation(ctx, "n", store.Attestation{TS: base.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutAttestation(ctx, "other", store.Attestation{TS: base}); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneAttestations(ctx, "n", 10); err != nil {
		t.Fatal(err)
	}
	got := s.Attestations("n")
	if len(got) != 10 || !got[0].TS.Equal(base.Add(2*time.Minute)) || !got[9].TS.Equal(base.Add(11*time.Minute)) {
		t.Fatalf("prune must keep the 10 newest, got %d from %v", len(got), got)
	}
	if len(s.Attestations("other")) != 1 {
		t.Error("prune must not touch another name's history")
	}
	if err := s.PruneAttestations(ctx, "n", 0); err == nil {
		t.Error("keeping fewer than one attestation must be refused")
	}
}
