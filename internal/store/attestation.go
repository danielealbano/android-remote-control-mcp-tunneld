package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type Attestation struct {
	TS             time.Time      `json:"ts"`
	Kind           string         `json:"kind"`
	AttestChainPEM string         `json:"attest_chain_pem"`
	ReportedDevice ReportedDevice `json:"reported_device,omitzero"`
}

const (
	AttestationKindEnroll = "enroll"
	AttestationKindIssue  = "issue"
)

func AttestationPrefix(name string) string { return "attestations/" + name + "/" }

func AttestationKey(name string, a Attestation) string {
	var r [2]byte
	rand.Read(r[:])
	return fmt.Sprintf("%s%s-%s.json", AttestationPrefix(name), a.TS.UTC().Format(tsNanosLayout), hex.EncodeToString(r[:]))
}
