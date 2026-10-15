package tunneltest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

func LooseACMEBudgets(c *config.ServeCmd) {
	c.ACMEGTSAccounts = []string{"gts"}
	for _, r := range []*string{&c.ACMEBudgetLEDomain, &c.ACMEBudgetLEOrders, &c.ACMEBudgetLEName,
		&c.ACMEBudgetGTSOrders, &c.ACMEBudgetGTSRequests, &c.ACMEBudgetGTSCertPolls,
		&c.ACMEBudgetZeroSSLOrders, &c.ACMEBudgetZeroSSLRequests} {
		*r = "100000/1m"
	}
	c.ACMEAttemptTimeoutLE, c.ACMEAttemptTimeoutGTS, c.ACMEAttemptTimeoutZeroSSL = time.Minute, time.Minute, time.Minute
	c.ACMEPollFirstLE, c.ACMEPollFirstGTS, c.ACMEPollFirstZeroSSL = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	c.ACMEPollInterval = 100 * time.Millisecond
}

type testACMEUser struct {
	key crypto.Signer
	reg *legoacme.ExtendedAccount
}

func (u *testACMEUser) GetEmail() string                           { return "ops@example.test" }
func (u *testACMEUser) GetRegistration() *legoacme.ExtendedAccount { return u.reg }
func (u *testACMEUser) GetPrivateKey() crypto.Signer               { return u.key }

func WriteACMEAccountKey(t *testing.T, accountDir, id string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(accountDir, "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

func RegisterACMEAccountKey(t *testing.T, accountDir, id, dirURL string) {
	t.Helper()
	user := &testACMEUser{key: WriteACMEAccountKey(t, accountDir, id)}
	lc := lego.NewConfig(user)
	lc.CADirURL = dirURL
	client, err := lego.NewClient(lc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		t.Fatal(err)
	}
}
