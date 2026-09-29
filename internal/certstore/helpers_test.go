package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testBundle creates a self-signed bundle for domain, valid for validFor.
func testBundle(t *testing.T, domain string, validFor time.Duration) *Bundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acctDER, err := x509.MarshalECPrivateKey(acct)
	if err != nil {
		t.Fatal(err)
	}
	return &Bundle{
		Domain:         domain,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		AccountKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: acctDER}),
		AccountURI:     "https://acme.example/acct/1",
		CADirURL:       "https://acme.example/directory",
		IssuedAt:       now.UTC().Truncate(time.Second),
		NotAfter:       tmpl.NotAfter.UTC().Truncate(time.Second),
	}
}

func assertBundleEqual(t *testing.T, got, want *Bundle) {
	t.Helper()
	if got.Domain != want.Domain || string(got.CertificatePEM) != string(want.CertificatePEM) ||
		string(got.PrivateKeyPEM) != string(want.PrivateKeyPEM) || string(got.AccountKeyPEM) != string(want.AccountKeyPEM) ||
		got.AccountURI != want.AccountURI || got.CADirURL != want.CADirURL ||
		!got.IssuedAt.Equal(want.IssuedAt) || !got.NotAfter.Equal(want.NotAfter) {
		t.Fatalf("bundle mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}
