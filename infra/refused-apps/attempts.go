package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sort"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

type attempt struct {
	At       time.Time `json:"at"`
	IP       string    `json:"ip"`
	Key      string    `json:"key"`
	Version  int64     `json:"version"`
	Verified bool      `json:"verified"`
}

type attemptList struct {
	LastReport string               `json:"last_report"`
	Apps       map[string][]attempt `json:"apps"`
}

type attemptID struct {
	app string
	at  int64
	ip  string
	key string
}

func idOf(app string, a attempt) attemptID {
	return attemptID{app: app, at: a.At.UnixNano(), ip: a.IP, key: a.Key}
}

func (l *attemptList) index() map[attemptID]bool {
	idx := make(map[attemptID]bool)
	for app, list := range l.Apps {
		for _, a := range list {
			idx[idOf(app, a)] = true
		}
	}
	return idx
}

func (l *attemptList) add(idx map[attemptID]bool, app string, a attempt) bool {
	id := idOf(app, a)
	if idx[id] {
		return false
	}
	idx[id] = true
	if l.Apps == nil {
		l.Apps = make(map[string][]attempt)
	}
	list := append(l.Apps[app], a)
	sort.SliceStable(list, func(i, j int) bool { return list[i].At.Before(list[j].At) })
	l.Apps[app] = list
	return true
}

func (l attemptList) without(hidden map[string]bool) attemptList {
	out := attemptList{LastReport: l.LastReport, Apps: make(map[string][]attempt, len(l.Apps))}
	for app, attempts := range l.Apps {
		if !hidden[app] {
			out.Apps[app] = attempts
		}
	}
	return out
}

func (l *attemptList) count() int {
	n := 0
	for _, list := range l.Apps {
		n += len(list)
	}
	return n
}

type revocationList interface {
	Revoked(serialHex string) bool
}

func toAttempt(ev store.RejectedEnrollment, revocations revocationList) (string, attempt) {
	app := ev.ClaimedPackage
	a := attempt{At: ev.TS.UTC(), IP: ev.SrcIP, Key: ev.SignerDigestHex}
	chain, err := parseChain([]byte(ev.AttestChainPEM))
	if err != nil || len(chain) == 0 {
		return app, a
	}
	kd, err := attest.ParseKeyDescription(chain[0])
	if err != nil {
		return app, a
	}
	app = kd.Package
	a.Version = kd.PackageVersion
	if a.Key == "" && len(kd.SignatureDigests) > 0 {
		a.Key = hex.EncodeToString(kd.SignatureDigests[0])
	}
	a.Verified = chainTrusted(ev.Reason) &&
		kd.SecurityLevel >= attest.SecurityTrustedEnvironment &&
		kd.HasRootOfTrust && kd.DeviceLocked && kd.VerifiedBootState == attest.BootVerified &&
		!anyRevoked(chain, revocations)
	return app, a
}

func chainTrusted(reason string) bool {
	switch reason {
	case "attest-challenge", "attest-signer", "attest-security-level", "attest-boot",
		"attest-device-unlocked", "attest-stale", "csr-mismatch":
		return true
	}
	return false
}

func anyRevoked(chain []*x509.Certificate, revocations revocationList) bool {
	for _, c := range chain {
		if revocations.Revoked(c.SerialNumber.Text(16)) {
			return true
		}
	}
	return false
}

func parseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return chain, nil
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
}
