package certwarden

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func TestCaddyModule(t *testing.T) {
	info := CertWarden{}.CaddyModule()
	if info.ID != "tls.get_certificate.certwarden" {
		t.Errorf("module ID = %q", info.ID)
	}
	if _, ok := info.New().(*CertWarden); !ok {
		t.Error("New() did not return *CertWarden")
	}
}

func TestProvisionLifecycle(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	cw := &CertWarden{
		BaseURL: m.url(),
		// Include an explicit subject (and a blank one, which must be skipped).
		Certificates: []CertConfig{{Name: "web", APIKey: "k", Subjects: []string{"web.example.com", ""}}},
	}
	if err := cw.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Defaults applied.
	if time.Duration(cw.RefreshInterval) != defaultRefreshInterval || time.Duration(cw.HTTPTimeout) != defaultHTTPTimeout {
		t.Errorf("defaults not applied: refresh=%v timeout=%v", time.Duration(cw.RefreshInterval), time.Duration(cw.HTTPTimeout))
	}
	if err := cw.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	cert, err := cw.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "web.example.com"})
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate: cert=%v err=%v", cert, err)
	}
	if err := cw.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestProvisionFailClosed(t *testing.T) {
	m := newMockCW(t)
	m.setStatus("web", http.StatusInternalServerError)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	cw := &CertWarden{
		BaseURL:      m.url(),
		FailClosed:   true,
		Certificates: []CertConfig{{Name: "web", APIKey: "k"}},
	}
	if err := cw.Provision(ctx); err == nil {
		t.Fatal("expected Provision to fail when fail_closed and the initial fetch errors")
	}
}

func TestProvisionFailOpen(t *testing.T) {
	m := newMockCW(t)
	m.setStatus("web", http.StatusInternalServerError)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	cw := &CertWarden{
		BaseURL:      m.url(),
		Certificates: []CertConfig{{Name: "web", APIKey: "k"}},
	}
	// Fail-open (default): startup succeeds even though the fetch failed.
	if err := cw.Provision(ctx); err != nil {
		t.Fatalf("fail-open Provision should not error: %v", err)
	}
	_ = cw.Cleanup()
}

func TestProvisionBadTrustedRoot(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	cw := &CertWarden{
		BaseURL:      "https://cw.example.com",
		TrustedRoots: []string{"/does/not/exist.pem"},
		Certificates: []CertConfig{{Name: "web", APIKey: "k"}},
	}
	if err := cw.Provision(ctx); err == nil {
		t.Fatal("expected Provision to fail when a trusted-root file is missing")
	}
}

func TestBuildHTTPClientTrustedRoots(t *testing.T) {
	dir := t.TempDir()

	// A valid CERTIFICATE PEM makes AppendCertsFromPEM succeed.
	certPEM := certBlocksOnly(t, makeBundlePEM(t, []string{"root.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	good := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(good, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cw := &CertWarden{HTTPTimeout: caddy.Duration(time.Second), TrustedRoots: []string{good}}
	c, err := cw.buildHTTPClient()
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Error("expected a custom RootCAs pool on the transport")
	}

	// A file with no certificates is an error.
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&CertWarden{TrustedRoots: []string{bad}}).buildHTTPClient(); err == nil {
		t.Error("expected error for a trusted-roots file with no certificates")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	input := `certwarden {
		base_url         https://certwarden.example.com
		api_path         /custom/download/path
		refresh_interval 6h
		http_timeout     10s
		cache_dir        /var/lib/caddy/cw
		fail_closed
		trusted_roots    /a.pem /b.pem
		certificate      web KEY1 alias.example.com extra.example.com
		certificate      api KEY2
	}`

	var cw CertWarden
	if err := cw.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if cw.BaseURL != "https://certwarden.example.com" {
		t.Errorf("base_url = %q", cw.BaseURL)
	}
	if cw.APIPath != "/custom/download/path" {
		t.Errorf("api_path = %q", cw.APIPath)
	}
	if time.Duration(cw.RefreshInterval) != 6*time.Hour {
		t.Errorf("refresh_interval = %v", time.Duration(cw.RefreshInterval))
	}
	if time.Duration(cw.HTTPTimeout) != 10*time.Second {
		t.Errorf("http_timeout = %v", time.Duration(cw.HTTPTimeout))
	}
	if cw.CacheDir != "/var/lib/caddy/cw" {
		t.Errorf("cache_dir = %q", cw.CacheDir)
	}
	if !cw.FailClosed {
		t.Error("fail_closed should be true")
	}
	if len(cw.TrustedRoots) != 2 || cw.TrustedRoots[0] != "/a.pem" || cw.TrustedRoots[1] != "/b.pem" {
		t.Errorf("trusted_roots = %v", cw.TrustedRoots)
	}
	if len(cw.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(cw.Certificates))
	}
	web := cw.Certificates[0]
	if web.Name != "web" || web.APIKey != "KEY1" {
		t.Errorf("cert[0] = %+v", web)
	}
	if len(web.Subjects) != 2 || web.Subjects[0] != "alias.example.com" || web.Subjects[1] != "extra.example.com" {
		t.Errorf("cert[0].subjects = %v", web.Subjects)
	}
	if cw.Certificates[1].Name != "api" || cw.Certificates[1].APIKey != "KEY2" {
		t.Errorf("cert[1] = %+v", cw.Certificates[1])
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	cases := map[string]string{
		"missing base_url arg":   "certwarden {\n base_url\n}",
		"missing api_path arg":   "certwarden {\n api_path\n}",
		"missing cache_dir arg":  "certwarden {\n cache_dir\n}",
		"missing refresh arg":    "certwarden {\n refresh_interval\n}",
		"missing http_timeout":   "certwarden {\n http_timeout\n}",
		"bad refresh_interval":   "certwarden {\n refresh_interval nope\n}",
		"bad http_timeout":       "certwarden {\n http_timeout nope\n}",
		"fail_closed with arg":   "certwarden {\n fail_closed yes\n}",
		"trusted_roots no args":  "certwarden {\n trusted_roots\n}",
		"certificate too few":    "certwarden {\n certificate onlyname\n}",
		"unknown option":         "certwarden {\n bogus value\n}",
		"arg after manager name": "certwarden extra {\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var cw CertWarden
			if err := cw.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Errorf("expected error for %q", name)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := CertWarden{
		BaseURL:      "https://cw.example.com",
		Certificates: []CertConfig{{Name: "web", APIKey: "k"}},
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	cases := map[string]CertWarden{
		"no base_url":  {Certificates: []CertConfig{{Name: "web", APIKey: "k"}}},
		"bad base_url": {BaseURL: "://nope", Certificates: []CertConfig{{Name: "web", APIKey: "k"}}},
		"no certs":     {BaseURL: "https://cw.example.com"},
		"no name":      {BaseURL: "https://cw.example.com", Certificates: []CertConfig{{APIKey: "k"}}},
		"no key":       {BaseURL: "https://cw.example.com", Certificates: []CertConfig{{Name: "web"}}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected validation error for %q", name)
			}
		})
	}
}

// TestModuleGetCertificate wires the store directly (bypassing caddy.Context)
// and checks the manager's GetCertificate serves managed names and passes
// through others.
func TestModuleGetCertificate(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	cw := &CertWarden{store: s}

	cert, err := cw.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "web.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a certificate for a managed name")
	}

	cert, err = cw.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "other.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate passthrough returned error: %v", err)
	}
	if cert != nil {
		t.Fatal("expected nil (pass-through) for an unmanaged name")
	}
}

func TestBuildHTTPClient(t *testing.T) {
	cw := &CertWarden{HTTPTimeout: caddy.Duration(7 * time.Second)}
	c, err := cw.buildHTTPClient()
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}
	if c.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", c.Timeout)
	}
	if _, ok := c.Transport.(*http.Transport); !ok {
		t.Error("expected *http.Transport")
	}

	// A non-existent trusted root path should error.
	cw2 := &CertWarden{TrustedRoots: []string{"/definitely/not/here.pem"}}
	if _, err := cw2.buildHTTPClient(); err == nil {
		t.Error("expected error for missing trusted root file")
	}
}
