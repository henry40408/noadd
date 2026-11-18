package tlsserve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func writeKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "noadd.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"noadd.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write := func(path, blockType string, bytes []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: bytes}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certFile, "CERTIFICATE", der)
	write(keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func TestStaticLoadsAPairAndRefusesOldProtocols(t *testing.T) {
	certFile, keyFile := writeKeyPair(t)
	config, err := Static(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Certificates) != 1 || config.MinVersion < 0x0303 {
		t.Fatalf("config = %+v", config)
	}
}

func TestStaticReportsAMissingFile(t *testing.T) {
	if _, err := Static("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Fatal("a missing pair was accepted")
	}
	certFile, _ := writeKeyPair(t)
	_, otherKey := writeKeyPair(t)
	if _, err := Static(certFile, otherKey); err == nil {
		t.Fatal("a mismatched pair was accepted")
	}
}

func TestACMEDefaultsToStagingAndPinsItsHosts(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "acme-cache")
	manager, err := ACME(ACMEConfig{Domains: []string{"a.example", "b.example"}, Email: "ops@example.com", Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Client == nil || manager.Client.DirectoryURL != stagingDirectory {
		t.Fatalf("client = %+v", manager.Client)
	}
	if manager.Email != "ops@example.com" || manager.Cache != autocert.DirCache(cache) {
		t.Fatalf("email %q cache %v", manager.Email, manager.Cache)
	}
	ctx := context.Background()
	if err := manager.HostPolicy(ctx, "b.example"); err != nil {
		t.Errorf("listed host refused: %v", err)
	}
	if err := manager.HostPolicy(ctx, "evil.example"); err == nil {
		t.Error("an unlisted host was allowed a certificate")
	}
}

func TestACMEProductionUsesTheLibraryDefaultDirectory(t *testing.T) {
	manager, err := ACME(ACMEConfig{Domains: []string{"a.example"}, Cache: t.TempDir(), Prod: true})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Client != nil {
		t.Fatalf("prod must leave the client unset, got %+v", manager.Client)
	}
}

func TestACMEWithoutADomainIsAnError(t *testing.T) {
	if _, err := ACME(ACMEConfig{Cache: t.TempDir()}); err == nil {
		t.Fatal("no domain was accepted")
	}
}
