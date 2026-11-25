package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	reportedFieldsLog = `level=INFO msg="the phone reported device properties in an unexpected form, so they are not recorded"`
	reportedObjectLog = `level=INFO msg="the phone reported its device in an unexpected form, so it is not recorded"`
)

func TestReportedDevice_KeepsOnlyConformingValues(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("m", reportedDeviceMaxLen)
	tests := []struct {
		name       string
		raw        string
		want       store.ReportedDevice
		wantLog    string
		wantFields string
	}{
		{name: "absent"},
		{name: "null", raw: `null`},
		{
			name: "all six",
			raw:  `{"brand":"brand-r","device":"device-r","product":"product-r","manufacturer":"maker-r","model":"Model R 5G","fingerprint":"brand-r/product-r/device-r:16/ID1/7:user/release-keys"}`,
			want: store.ReportedDevice{Brand: "brand-r", Device: "device-r", Product: "product-r", Manufacturer: "maker-r", Model: "Model R 5G",
				Fingerprint: "brand-r/product-r/device-r:16/ID1/7:user/release-keys"},
		},
		{name: "not an object", raw: `"model-r"`, wantLog: reportedObjectLog},
		{name: "an array", raw: `[1]`, wantLog: reportedObjectLog},
		{name: "number value", raw: `{"brand":"brand-r","model":7}`, want: store.ReportedDevice{Brand: "brand-r"}, wantLog: reportedFieldsLog, wantFields: "fields=[model]"},
		{name: "control character", raw: `{"brand":"brand-r","model":"a\nb"}`, want: store.ReportedDevice{Brand: "brand-r"}, wantLog: reportedFieldsLog, wantFields: "fields=[model]"},
		{name: "longest value", raw: `{"model":"` + long + `"}`, want: store.ReportedDevice{Model: long}},
		{name: "too long", raw: `{"brand":"brand-r","model":"` + long + `m"}`, want: store.ReportedDevice{Brand: "brand-r"}, wantLog: reportedFieldsLog, wantFields: "fields=[model]"},
		{name: "empty and null values", raw: `{"model":"","brand":null}`},
		{name: "unknown field", raw: `{"serial":"123","model":"model-r"}`, want: store.ReportedDevice{Model: "model-r"}},
		{name: "non-ASCII", raw: `{"model":"Modèle – R"}`, want: store.ReportedDevice{Model: "Modèle – R"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, buf := newHistoryService(t, tunneltest.NewStore(), fakeVerifier{}, false)
			var raw json.RawMessage
			if tc.raw != "" {
				raw = json.RawMessage(tc.raw)
			}
			if got := svc.reportedDevice("tun", "1.2.3.4", raw); got != tc.want {
				t.Errorf("reported device = %+v, want %+v", got, tc.want)
			}
			out := buf.String()
			if tc.wantLog == "" {
				if strings.Contains(out, "unexpected form") {
					t.Errorf("nothing must be logged, got:\n%s", out)
				}
				return
			}
			for _, want := range []string{tc.wantLog, "tunnel=tun", "ip=1.2.3.4", tc.wantFields} {
				if !strings.Contains(out, want) {
					t.Errorf("log must contain %q, got:\n%s", want, out)
				}
			}
		})
	}
}

func TestEnrollIssue_RecordTheReportedDevice(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
	first := store.ReportedDevice{Model: "model-r", Fingerprint: "brand-r/product-r/device-r:15/ID1/1:user/release-keys"}
	second := store.ReportedDevice{Model: "model-r", Fingerprint: "brand-r/product-r/device-r:16/ID2/2:user/release-keys"}
	reportedJSON := func(r store.ReportedDevice) json.RawMessage {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	assertRecord := func(name string, want store.ReportedDevice) {
		t.Helper()
		rec, err := st.GetName(context.Background(), name)
		if err != nil || rec.ReportedDevice != want {
			t.Fatalf("name record reports %+v (err %v), want %+v", rec.ReportedDevice, err, want)
		}
	}

	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, AttestChainPEM: []byte(testChainPEM), ReportedDevice: reportedJSON(first),
	})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	name := res.Name
	assertRecord(name, first)

	issue := func(at int64, reported json.RawMessage) {
		t.Helper()
		svc.SetClock(func() time.Time { return time.Unix(at, 0) })
		if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
			Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
			AttestChainPEM: []byte(testChainPEM), ReportedDevice: reported,
		}); ee != nil {
			t.Fatalf("issue failed: %v", ee)
		}
	}
	issue(1_700_000_100, reportedJSON(second))
	assertRecord(name, second)
	issue(1_700_000_200, nil)
	assertRecord(name, second)

	got := st.Attestations(name)
	if len(got) != 3 || got[0].ReportedDevice != first || got[1].ReportedDevice != second || got[2].ReportedDevice != (store.ReportedDevice{}) {
		t.Fatalf("each history entry must carry what its request reported, got %+v", got)
	}
}

func TestIssue_ReportedDeviceNeverRefusesTheCertificateRequest(t *testing.T) {
	t.Parallel()
	enrolled := store.ReportedDevice{Model: "model-r"}
	for _, raw := range []string{`7`, `"model-r"`, `[1]`, `{"model":["x"],"brand":{}}`, `{"model":"a\nb"}`} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			st := tunneltest.NewStore()
			idCSR, idPub := newCSR(t)
			svc, _ := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
			res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{
				Nonce: mintNonce(t, svc), IdentityCSR: idCSR, AttestChainPEM: []byte(testChainPEM), ReportedDevice: json.RawMessage(`{"model":"model-r"}`),
			})
			if ee != nil {
				t.Fatalf("enroll failed: %v", ee)
			}
			svc.SetClock(func() time.Time { return time.Unix(1_700_000_100, 0) })
			if _, ee := svc.Issue(context.Background(), res.Name, "1.2.3.4", Request{
				Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, res.Name+".example.test"),
				AttestChainPEM: []byte(testChainPEM), ReportedDevice: json.RawMessage(raw),
			}); ee != nil {
				t.Fatalf("a malformed reported_device must not refuse the certificate request, got %v", ee)
			}
			if rec, err := st.GetName(context.Background(), res.Name); err != nil || rec.ReportedDevice != enrolled || rec.CA == "" {
				t.Fatalf("name record = %+v (err %v), want the issued cert and the enrollment's reported device %+v", rec, err, enrolled)
			}
			if got := st.Attestations(res.Name); len(got) != 2 || got[1].ReportedDevice != (store.ReportedDevice{}) {
				t.Fatalf("the certificate request's history entry must report nothing, got %+v", got)
			}
		})
	}
}

func TestIssue_OptionalAttestationStillRecordsTheReportedDevice(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{}, true)
	name := enrollWithChain(t, svc, idCSR)
	reported := store.ReportedDevice{Model: "model-r"}
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
		AttestChainPEM: []byte(testChainPEM), ReportedDevice: json.RawMessage(`{"model":"model-r"}`),
	}); ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}
	if rec, err := st.GetName(context.Background(), name); err != nil || rec.ReportedDevice != reported {
		t.Fatalf("name record reports %+v (err %v), want %+v", rec.ReportedDevice, err, reported)
	}
	if got := st.Attestations(name); len(got) != 0 {
		t.Fatalf("the optional mode keeps no history, got %+v", got)
	}
}

func TestHandler_ReportedDeviceNeverRefusesTheEnrollment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want store.ReportedDevice
	}{
		{name: "object", raw: `{"model":"model-r","fingerprint":"brand-r/product-r/device-r:16/ID1/7:user/release-keys"}`,
			want: store.ReportedDevice{Model: "model-r", Fingerprint: "brand-r/product-r/device-r:16/ID1/7:user/release-keys"}},
		{name: "wrong type", raw: `7`},
		{name: "wrong value types", raw: `{"model":["x"],"brand":{}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := tunneltest.NewStore()
			idCSR, idPub := newCSR(t)
			svc, _ := newService(t, Config{CA: testCA(t), Names: st, Evidence: st,
				Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{}})
			h := newTestHandler(t, svc, nil)
			b, err := json.Marshal(enrollRequestBody{Nonce: hexEncode(mintNonce(t, svc)), IdentityCSR: csrPEM(t, idCSR), ReportedDevice: json.RawMessage(tc.raw)})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
			req.RemoteAddr = "203.0.113.18:5000"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != 200 {
				t.Fatalf("enroll failed: %d %s", rr.Code, rr.Body.String())
			}
			var resp enrollResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if rec, err := st.GetName(context.Background(), resp.Name); err != nil || rec.ReportedDevice != tc.want {
				t.Fatalf("name record reports %+v (err %v), want %+v", rec.ReportedDevice, err, tc.want)
			}
		})
	}
}
