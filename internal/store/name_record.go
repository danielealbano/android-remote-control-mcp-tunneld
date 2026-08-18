package store

import "time"

// DeviceInfo holds the device scalars pulled from the attestation KeyDescription (helpful for
// debugging; NEVER the full chain). All seven agreed scalars: os version + three patch levels +
// attestation/keymint versions + the security-level string.
type DeviceInfo struct {
	OSVersion          int    `json:"os_version"`
	OSPatch            int    `json:"os_patch"`
	VendorPatch        int    `json:"vendor_patch"`
	BootPatch          int    `json:"boot_patch"`
	AttestationVersion int    `json:"attestation_version"`
	KeymintVersion     int    `json:"keymint_version"`
	SecurityLevel      string `json:"security_level"`
}

// CertInfo is the shared public-cert metadata: which CA issued it and the serial/validity/ARI id.
// not_before anchors the fixed GTS/ZeroSSL renewal cadence (NotBefore + (160h - margin)).
type CertInfo struct {
	CA        string    `json:"ca"` // "letsencrypt" | "gts" | "zerossl"
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ARIID     string    `json:"ari_id"`
}

// CertRecord is the registry's cert sub-object. Per the durable schema, the issuing CA lives
// TOP-LEVEL on NameRecord — NEVER inside cert.
type CertRecord struct {
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ARIID     string    `json:"ari_id"`
}

// NameRecord is the names/<name> registry object. The issuing CA lives TOP-LEVEL (sibling of cert);
// claim_nonce is the write-verify claim discriminator (16 crypto-random bytes hex), written at claim
// time and PRESERVED on every LWW update. It NEVER stores cert PEM, private keys, or attestation
// chains for accepted enrollments.
type NameRecord struct {
	Schema        int        `json:"schema"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastRenewedAt time.Time  `json:"last_renewed_at"`
	IdentityKeyFP string     `json:"identity_key_fpr"`
	ClaimNonce    string     `json:"claim_nonce"`
	CA            string     `json:"ca"` // top-level issuing CA — the ONLY place the CA is stored
	Cert          CertRecord `json:"cert"`
	Device        DeviceInfo `json:"device"`
}

// SetCert populates the top-level CA and the cert sub-object from an issuer's CertInfo.
func (r *NameRecord) SetCert(info CertInfo) {
	r.CA = info.CA
	r.Cert = CertRecord{Serial: info.Serial, NotBefore: info.NotBefore, NotAfter: info.NotAfter, ARIID: info.ARIID}
}

// CertInfo reassembles the shared cert metadata from the top-level CA + the cert sub-object.
func (r *NameRecord) CertInfo() CertInfo {
	return CertInfo{CA: r.CA, Serial: r.Cert.Serial, NotBefore: r.Cert.NotBefore, NotAfter: r.Cert.NotAfter, ARIID: r.Cert.ARIID}
}
