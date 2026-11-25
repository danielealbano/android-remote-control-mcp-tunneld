package attest

import (
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

func allDeviceIDs() map[int]string {
	return map[int]string{
		tagIDBrand: "brand-x", tagIDDevice: "device-x", tagIDProduct: "product-x",
		tagIDManufacturer: "maker-x", tagIDModel: "model-x",
	}
}

func TestParseKeyDescription_DeviceIDs(t *testing.T) {
	t.Parallel()
	full := [5]string{"brand-x", "device-x", "product-x", "maker-x", "model-x"}
	tests := []struct {
		name    string
		mutate  func(*chainParams)
		want    [5]string
		wantErr bool
	}{
		{name: "absent", mutate: func(*chainParams) {}},
		{name: "all five in the TEE list", mutate: func(p *chainParams) { p.deviceIDs = allDeviceIDs() }, want: full},
		{name: "only the model", mutate: func(p *chainParams) { p.deviceIDs = map[int]string{tagIDModel: "model-x"} }, want: [5]string{4: "model-x"}},
		{name: "software list only is ignored", mutate: func(p *chainParams) { p.deviceIDs, p.deviceIDsInSoftware = allDeviceIDs(), true }},
		{name: "a string type other than OCTET STRING is read", mutate: func(p *chainParams) { p.deviceIDs, p.deviceIDsAsUTF8 = allDeviceIDs(), true }, want: full},
		{name: "a malformed value fails the parse", mutate: func(p *chainParams) { p.malformedDeviceID = true }, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := defaultParams()
			tc.mutate(&p)
			chain, _ := newFakeCA(t).buildChain(t, p)
			kd, err := ParseKeyDescription(chain[0])
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseKeyDescription error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got := [5]string{kd.Brand, kd.Device, kd.Product, kd.Manufacturer, kd.Model}; got != tc.want {
				t.Errorf("device ids = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerify_CarriesTheDeviceProperties(t *testing.T) {
	t.Parallel()
	ca := newFakeCA(t)
	p := defaultParams()
	p.deviceIDs = allDeviceIDs()
	chain, _ := ca.buildChain(t, p)
	res, err := testVerifier(t, ca, p.signerDigest, nil, frozenNow()).Verify(chain, p.challenge, frozenNow())
	if err != nil {
		t.Fatalf("a chain with device properties must pass: %v", err)
	}
	want := store.DeviceInfo{
		OSVersion: 160000, OSPatch: 202607, VendorPatch: 202607, BootPatch: 202607, AttestationVersion: 200, KeymintVersion: 200,
		SecurityLevel: "tee", Brand: "brand-x", Device: "device-x", Product: "product-x", Manufacturer: "maker-x", Model: "model-x",
	}
	if res.Device != want {
		t.Errorf("device = %+v, want %+v", res.Device, want)
	}
}
