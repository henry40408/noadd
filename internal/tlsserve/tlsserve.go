// Package tlsserve builds the TLS configuration of the HTTP listener: a static
// certificate pair, or Let's Encrypt certificates obtained on demand.
package tlsserve

import (
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// stagingDirectory is Let's Encrypt's staging CA, which issues untrusted
// certificates and is therefore the default until ACMEConfig.Prod is set.
const stagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Static loads a certificate and key pair. The pair is read once; a renewed
// certificate needs a restart, as it did in the Rust server.
func Static(certFile, keyFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ACMEConfig configures automatic certificates.
type ACMEConfig struct {
	Domains []string
	// Email is the optional contact address.
	Email string
	// Cache is the directory certificates and the account key persist in.
	Cache string
	// Prod selects Let's Encrypt production instead of staging.
	Prod bool
}

// ACME returns the certificate manager. Its TLSConfig answers the
// tls-alpn-01 challenge on the listener's own port, so no port 80 is needed.
func ACME(cfg ACMEConfig) (*autocert.Manager, error) {
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("ACME needs at least one domain")
	}
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.Cache),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
	}
	if !cfg.Prod {
		manager.Client = &acme.Client{DirectoryURL: stagingDirectory}
	}
	return manager, nil
}
