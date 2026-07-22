package certwarden

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAPIPath is the Cert Warden download endpoint that returns a combined
// private key + certificate chain PEM bundle for a named certificate. The
// certificate name is appended to this path. It matches the "PEM: Private Key
// + Certificate Chain" download URL shown per-certificate in the Cert Warden
// UI; override apiPath if a future Cert Warden version changes it.
const DefaultAPIPath = "/certwarden/api/v1/download/privatecertchains"

// apiKeyHeader is the header Cert Warden accepts for download authentication.
// The value is the combined certificate + private-key API key exactly as shown
// in the Cert Warden UI for the certificate.
const apiKeyHeader = "X-API-Key"

// maxBundleBytes bounds how much of a download response we will read, guarding
// against a misbehaving or hostile endpoint. A key + full chain is a few KiB.
const maxBundleBytes = 1 << 20 // 1 MiB

// errNotManaged is returned when Cert Warden replies 204 No Content, meaning it
// is not serving a certificate for the requested name.
var errNotManaged = errors.New("certwarden: endpoint is not managing this certificate")

// httpStatusError describes a non-success HTTP response from Cert Warden.
type httpStatusError struct {
	status int
	body   string
}

func (e *httpStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("certwarden: unexpected HTTP status %d", e.status)
	}
	return fmt.Sprintf("certwarden: unexpected HTTP status %d: %s", e.status, e.body)
}

// client fetches certificate bundles from a Cert Warden instance.
type client struct {
	baseURL string
	apiPath string
	http    *http.Client
}

// newClient builds a client. baseURL is the Cert Warden root (e.g.
// https://certwarden.example.com); apiPath defaults to DefaultAPIPath when
// empty. The provided *http.Client governs timeouts and TLS trust.
func newClient(baseURL, apiPath string, httpClient *http.Client) *client {
	if apiPath == "" {
		apiPath = DefaultAPIPath
	}
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiPath: "/" + strings.Trim(apiPath, "/"),
		http:    httpClient,
	}
}

// downloadURL returns the fully-qualified URL for a named certificate. The name
// is path-escaped so a value containing spaces or reserved characters produces
// a well-formed request.
func (c *client) downloadURL(name string) string {
	return c.baseURL + c.apiPath + "/" + url.PathEscape(name)
}

// fetch retrieves and parses the named certificate from Cert Warden. It returns
// errNotManaged when the endpoint replies 204, and an *httpStatusError for
// other non-200 responses.
func (c *client) fetch(ctx context.Context, name, apiKey string) (*parsedCert, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.downloadURL(name), nil)
	if err != nil {
		return nil, fmt.Errorf("certwarden: building request: %w", err)
	}
	req.Header.Set(apiKeyHeader, apiKey)
	req.Header.Set("Accept", "application/x-pem-file")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certwarden: fetching %q: %w", name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusNoContent:
		return nil, errNotManaged
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &httpStatusError{status: resp.StatusCode, body: strings.TrimSpace(string(snippet))}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes))
	if err != nil {
		return nil, fmt.Errorf("certwarden: reading response for %q: %w", name, err)
	}
	pc, err := parseBundle(body)
	if err != nil {
		return nil, fmt.Errorf("certwarden: parsing bundle for %q: %w", name, err)
	}
	return pc, nil
}

// parsedCert is a usable TLS certificate plus metadata extracted from its leaf.
type parsedCert struct {
	tlsCert  *tls.Certificate
	names    []string  // lowercased DNS SANs the leaf is valid for
	notAfter time.Time // leaf expiry
	lifetime time.Duration
	pem      []byte // original bundle, retained for on-disk persistence
}

// parseBundle parses a Cert Warden "private key + certificate chain" PEM bundle
// into a tls.Certificate, using only the standard library. The bundle contains
// one PRIVATE KEY block and one or more CERTIFICATE blocks in any order.
func parseBundle(bundle []byte) (*parsedCert, error) {
	var certPEM, keyPEM bytes.Buffer
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			if keyPEM.Len() > 0 {
				continue // keep the first key; ignore extras
			}
			_ = pem.Encode(&keyPEM, block)
		case block.Type == "CERTIFICATE":
			_ = pem.Encode(&certPEM, block)
		}
	}
	if certPEM.Len() == 0 {
		return nil, errors.New("no CERTIFICATE block found in bundle")
	}
	if keyPEM.Len() == 0 {
		return nil, errors.New("no PRIVATE KEY block found in bundle")
	}

	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("key/certificate pair invalid: %w", err)
	}

	// Parse the leaf explicitly: tls.X509KeyPair does not populate Leaf on
	// older Go versions, and we need the SANs + expiry regardless.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	tlsCert.Leaf = leaf

	names := make([]string, 0, len(leaf.DNSNames))
	seen := make(map[string]struct{}, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}

	return &parsedCert{
		tlsCert:  &tlsCert,
		names:    names,
		notAfter: leaf.NotAfter,
		lifetime: leaf.NotAfter.Sub(leaf.NotBefore),
		pem:      append([]byte(nil), bundle...),
	}, nil
}
