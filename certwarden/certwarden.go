// Package certwarden provides a Caddy TLS certificate manager that serves
// certificates issued and stored by a Cert Warden instance
// (https://www.certwarden.com).
//
// Unlike Caddy's built-in tls.get_certificate.http manager, which calls its
// backend on every TLS handshake, this module keeps certificates in an
// in-memory cache and refreshes them in the background, so the handshake path
// never performs network I/O. It is intended for high-traffic proxies serving
// many hosts from a central Cert Warden.
package certwarden

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CertWarden{})
}

const (
	defaultRefreshInterval = 12 * time.Hour
	defaultHTTPTimeout     = 30 * time.Second
)

// CertConfig identifies one certificate to fetch from Cert Warden.
type CertConfig struct {
	// Name is the Cert Warden certificate name (as shown in its UI). Required.
	Name string `json:"name"`

	// APIKey is the combined download API key for this certificate's
	// "Private Key + Certificate Chain" download, as shown in the Cert Warden
	// UI. Supports Caddy placeholders such as {env.VAR}. Required.
	APIKey string `json:"api_key"`

	// Subjects optionally overrides the SNI names this certificate answers for.
	// When empty (the default), the certificate's own DNS SANs are used.
	Subjects []string `json:"subjects,omitempty"`
}

// CertWarden is a certificate manager (tls.get_certificate.certwarden) that
// serves certificates fetched from a Cert Warden instance, cached in memory and
// refreshed in the background.
type CertWarden struct {
	// BaseURL is the Cert Warden root URL, e.g. https://certwarden.example.com.
	// Required. Supports Caddy placeholders.
	BaseURL string `json:"base_url,omitempty"`

	// APIPath overrides the download endpoint path. Defaults to
	// /certwarden/api/v1/download/privatecertchains (the certificate name is
	// appended). Set this only if your Cert Warden version uses a different path.
	APIPath string `json:"api_path,omitempty"`

	// Certificates is the set of certificates to manage. At least one required.
	Certificates []CertConfig `json:"certificates,omitempty"`

	// RefreshInterval is the ceiling on how often each certificate is
	// re-fetched. Certificates are also refreshed earlier as they near expiry.
	// Default 12h.
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`

	// HTTPTimeout bounds each request to Cert Warden. Default 30s.
	HTTPTimeout caddy.Duration `json:"http_timeout,omitempty"`

	// CacheDir, when set, enables an on-disk cache of fetched bundles (0600) so
	// certificates survive a restart even if Cert Warden is unreachable.
	CacheDir string `json:"cache_dir,omitempty"`

	// FailClosed makes provisioning fail if the initial fetch of any certificate
	// fails. By default the module starts anyway and retries in the background.
	FailClosed bool `json:"fail_closed,omitempty"`

	// TrustedRoots is an optional list of PEM file paths to trust when
	// connecting to Cert Warden (in addition to the system pool). Only needed if
	// the Cert Warden endpoint is not served with a publicly trusted certificate.
	TrustedRoots []string `json:"trusted_roots,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
	store  *store
}

// CaddyModule returns the Caddy module information.
func (CertWarden) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.certwarden",
		New: func() caddy.Module { return new(CertWarden) },
	}
}

// Provision sets up the HTTP client, seeds the cache from disk (if enabled),
// performs an initial fetch, and starts the background refresher.
func (cw *CertWarden) Provision(ctx caddy.Context) error {
	cw.ctx = ctx
	cw.logger = ctx.Logger()

	repl := caddy.NewReplacer()
	cw.BaseURL = repl.ReplaceAll(cw.BaseURL, "")

	if cw.RefreshInterval <= 0 {
		cw.RefreshInterval = caddy.Duration(defaultRefreshInterval)
	}
	if cw.HTTPTimeout <= 0 {
		cw.HTTPTimeout = caddy.Duration(defaultHTTPTimeout)
	}

	httpClient, err := cw.buildHTTPClient()
	if err != nil {
		return err
	}
	cl := newClient(cw.BaseURL, cw.APIPath, httpClient)

	managed := make([]*managedCert, 0, len(cw.Certificates))
	for _, c := range cw.Certificates {
		subs := make([]string, 0, len(c.Subjects))
		for _, s := range c.Subjects {
			s = strings.ToLower(strings.TrimSpace(repl.ReplaceAll(s, "")))
			if s != "" {
				subs = append(subs, s)
			}
		}
		managed = append(managed, &managedCert{
			name:             repl.ReplaceAll(c.Name, ""),
			apiKey:           repl.ReplaceAll(c.APIKey, ""),
			explicitSubjects: subs,
		})
	}

	cw.store = newStore(cl, cw.logger, managed, time.Duration(cw.RefreshInterval), cw.CacheDir)
	cw.store.loadDiskCache()

	if err := cw.store.prewarm(ctx); err != nil {
		if cw.FailClosed {
			return fmt.Errorf("certwarden: initial certificate fetch failed (fail_closed): %w", err)
		}
		cw.logger.Warn("initial certificate fetch had errors; will retry in the background",
			zap.Error(err))
	}

	go cw.store.run(ctx)
	return nil
}

// Validate checks the configuration.
func (cw *CertWarden) Validate() error {
	if cw.BaseURL == "" {
		return errors.New("certwarden: base_url is required")
	}
	if u, err := url.Parse(cw.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("certwarden: base_url %q is not a valid absolute URL", cw.BaseURL)
	}
	if len(cw.Certificates) == 0 {
		return errors.New("certwarden: at least one certificate must be configured")
	}
	for i, c := range cw.Certificates {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("certwarden: certificates[%d].name is required", i)
		}
		if strings.TrimSpace(c.APIKey) == "" {
			return fmt.Errorf("certwarden: certificates[%d].api_key is required", i)
		}
	}
	return nil
}

// GetCertificate returns the cached certificate for the handshake's SNI, or
// (nil, nil) to indicate this manager does not serve that name. It performs no
// network I/O and is safe to call on every handshake.
func (cw *CertWarden) GetCertificate(_ context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cw.store.getCertificate(hello.ServerName), nil
}

// Cleanup stops the background refresher.
func (cw *CertWarden) Cleanup() error {
	if cw.store != nil {
		cw.store.stop()
	}
	return nil
}

// buildHTTPClient constructs the HTTP client used to talk to Cert Warden,
// honoring the configured timeout and any additional trusted roots.
func (cw *CertWarden) buildHTTPClient() (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(cw.TrustedRoots) > 0 {
		pool := x509.NewCertPool()
		for _, path := range cw.TrustedRoots {
			pemBytes, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("certwarden: reading trusted root %q: %w", path, err)
			}
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("certwarden: no certificates found in trusted root %q", path)
			}
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout:   time.Duration(cw.HTTPTimeout),
		Transport: transport,
	}, nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration:
//
//	get_certificate certwarden {
//	    base_url         https://certwarden.example.com
//	    api_path         /certwarden/api/v1/download/privatecertchains
//	    refresh_interval 12h
//	    http_timeout     30s
//	    cache_dir        /var/lib/caddy/certwarden
//	    fail_closed
//	    trusted_roots    /etc/caddy/certwarden-root.pem
//	    certificate      <name> <api_key> [subject...]
//	    certificate      <name2> <api_key2>
//	}
func (cw *CertWarden) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the manager name ("certwarden")
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "base_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cw.BaseURL = d.Val()
		case "api_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cw.APIPath = d.Val()
		case "refresh_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing refresh_interval: %v", err)
			}
			cw.RefreshInterval = caddy.Duration(dur)
		case "http_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing http_timeout: %v", err)
			}
			cw.HTTPTimeout = caddy.Duration(dur)
		case "cache_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cw.CacheDir = d.Val()
		case "fail_closed":
			if d.NextArg() {
				return d.ArgErr()
			}
			cw.FailClosed = true
		case "trusted_roots":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			cw.TrustedRoots = append(cw.TrustedRoots, args...)
		case "certificate":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return d.Errf("certificate requires at least <name> <api_key>")
			}
			cw.Certificates = append(cw.Certificates, CertConfig{
				Name:     args[0],
				APIKey:   args[1],
				Subjects: args[2:],
			})
		default:
			return d.Errf("unrecognized certwarden option %q", d.Val())
		}
	}
	return nil
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*CertWarden)(nil)
	_ caddy.Validator       = (*CertWarden)(nil)
	_ caddy.CleanerUpper    = (*CertWarden)(nil)
	_ certmagic.Manager     = (*CertWarden)(nil)
	_ caddyfile.Unmarshaler = (*CertWarden)(nil)
)
