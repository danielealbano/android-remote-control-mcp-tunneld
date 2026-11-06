package acme

import (
	"context"
	"log/slog"
)

var legoMessages = map[string]string{
	"Registering the account.":                                "registering the account with the certificate authority",
	"Registering the account (EAB).":                          "registering the account with the certificate authority, linked to the operator's account there",
	"Trying to resolve the account by key":                    "looking up the existing account at the certificate authority by its key",
	"Obtaining bundled SAN certificate given a CSR.":          "ordering a certificate with its full chain from the certificate authority",
	"Validations succeeded; requesting certificates.":         "every name in the order passed validation, so the certificate is requested",
	"Waiting for certificates.":                               "waiting for the certificate authority to finish the certificate",
	"Server responded with a certificate.":                    "received the certificate from the certificate authority",
	"Unable to get the authorization.":                        "could not read a name validation of a failed order back from the certificate authority, so it is not deactivated",
	"Skipping deactivating of valid authorization.":           "kept a name validation of a failed order that already passed; it is not deactivated",
	"Deactivating authorization.":                             "deactivating a name validation of a failed order at the certificate authority",
	"Unable to deactivate the authorization.":                 "could not deactivate a name validation at the certificate authority, so it is left as it is",
	"Authorization is already valid; skipping the challenge.": "the certificate authority already holds a passed validation for this name, so no new proof is needed",
	"sequence: wait.":                                         "waiting before the next name's validation, because the DNS provider handles one at a time",
	"Cleaning up failed.":                                     "could not remove the proof of control for a name after its validation, so it is left in place",
	"Use solver.":                                             "chose how to prove control of the name to the certificate authority",
	"No available solvers were found for the challenge.":      "the certificate authority offered no validation method this node is set up for, so the name cannot be validated",
	"The server validated our request.":                       "the certificate authority confirmed control of the name",
	"tlsalpn01: Trying to solve TLS-ALPN-01.":                 "proving control of the name with a TLS-ALPN-01 validation",
	"tlsalpn01: cleaning up failed.":                          "could not remove the TLS-ALPN-01 validation answer after the check, so it is left in place",
	"http01: Trying to solve HTTP-01.":                        "proving control of the name with an HTTP-01 validation",
	"http01: cleaning up failed.":                             "could not remove the HTTP-01 validation answer after the check, so it is left in place",
	"dns01: challenge option skipped.":                        "ignored a DNS-01 validation setting that could not be applied",
	"dns01: preparing to solve the challenge.":                "creating the DNS-01 validation record for the name",
	"dns01: trying to solve the challenge.":                   "proving control of the name with a DNS-01 validation",
	"dns01: waiting for record propagation":                   "waiting for the DNS-01 validation record to be visible in DNS",
	"dns01: waiting for record propagation.":                  "the DNS-01 validation record is not visible in DNS yet, so it is checked again",
	"dns01: cleaning DNS-01 challenge.":                       "removing the DNS-01 validation record for the name",
	"dns01: Found CNAME entry.":                               "followed a CNAME for the DNS-01 validation record to the name it points to",
	"Failed to parse Retry-After header.":                     "could not read the wait time the certificate authority asked for, so none is used",
	"skip domain: unable to Punycode encode.":                 "left a name out of the certificate order because it cannot be converted to its DNS form",
	"Failed to read the file.":                                "could not read a DNS provider setting from its file, so the setting is empty",
}

type readableLegoHandler struct{ slog.Handler }

func (h readableLegoHandler) Handle(ctx context.Context, r slog.Record) error {
	if msg, ok := legoMessages[r.Message]; ok {
		r.Message = msg
	}
	return h.Handler.Handle(ctx, r)
}

func (h readableLegoHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return readableLegoHandler{h.Handler.WithAttrs(attrs)}
}

func (h readableLegoHandler) WithGroup(name string) slog.Handler {
	return readableLegoHandler{h.Handler.WithGroup(name)}
}
