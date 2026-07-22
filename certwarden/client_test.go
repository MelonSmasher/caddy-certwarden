package certwarden

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPStatusErrorFormat(t *testing.T) {
	if got := (&httpStatusError{status: 500}).Error(); !strings.Contains(got, "500") {
		t.Errorf("status-only error missing code: %q", got)
	}
	got := (&httpStatusError{status: 502, body: "bad gateway"}).Error()
	if !strings.Contains(got, "502") || !strings.Contains(got, "bad gateway") {
		t.Errorf("error missing status or body: %q", got)
	}
}

func TestParseBundle(t *testing.T) {
	now := time.Now()
	valid := makeBundlePEM(t, []string{"A.Example.com", "b.example.com", "b.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))

	pc, err := parseBundle(valid)
	if err != nil {
		t.Fatalf("parseBundle valid: %v", err)
	}
	if pc.tlsCert == nil || pc.tlsCert.Leaf == nil {
		t.Fatal("expected tlsCert with populated Leaf")
	}
	// SANs should be lowercased and de-duplicated.
	wantNames := map[string]bool{"a.example.com": true, "b.example.com": true}
	if len(pc.names) != len(wantNames) {
		t.Fatalf("names = %v, want 2 unique lowercased", pc.names)
	}
	for _, n := range pc.names {
		if !wantNames[n] {
			t.Errorf("unexpected SAN %q", n)
		}
	}
	if pc.lifetime <= 0 || pc.notAfter.Before(now) {
		t.Errorf("bad lifetime/notAfter: %v / %v", pc.lifetime, pc.notAfter)
	}

	// Extract just the cert / just the key to test the missing-block errors.
	certOnly := certBlocksOnly(t, valid)
	if _, err := parseBundle(certOnly); err == nil {
		t.Error("expected error for bundle with no private key")
	}
	keyOnly := keyBlocksOnly(t, valid)
	if _, err := parseBundle(keyOnly); err == nil {
		t.Error("expected error for bundle with no certificate")
	}
	if _, err := parseBundle([]byte("not pem at all")); err == nil {
		t.Error("expected error for non-PEM input")
	}

	// A bundle with two private keys keeps the first and ignores the extra.
	b1 := makeBundlePEM(t, []string{"a.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	b2 := makeBundlePEM(t, []string{"b.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	combined := append(append([]byte{}, b1...), b2...)
	pc, err = parseBundle(combined)
	if err != nil {
		t.Fatalf("parseBundle two-key bundle: %v", err)
	}
	if len(pc.names) != 1 || pc.names[0] != "a.example.com" {
		t.Errorf("expected leaf from first key/cert, got names %v", pc.names)
	}

	// A key that doesn't match the certificate (corrupt server response).
	mismatched := append(keyBlocksOnly(t, b1), certBlocksOnly(t, b2)...)
	if _, err := parseBundle(mismatched); err == nil {
		t.Error("expected error when the private key does not match the certificate")
	}
}

func TestClientFetch(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	m.setKey("web", "secret-key")

	c := newClient(m.url(), "", &http.Client{Timeout: 5 * time.Second})
	ctx := context.Background()

	// Success with correct key.
	pc, err := c.fetch(ctx, "web", "secret-key")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(pc.names) != 1 || pc.names[0] != "web.example.com" {
		t.Fatalf("unexpected names %v", pc.names)
	}

	// Wrong key -> 401 -> httpStatusError.
	if _, err := c.fetch(ctx, "web", "wrong"); err == nil {
		t.Error("expected error with wrong api key")
	} else {
		var se *httpStatusError
		if !errors.As(err, &se) || se.status != http.StatusUnauthorized {
			t.Errorf("expected 401 httpStatusError, got %v", err)
		}
	}

	// 204 -> errNotManaged.
	m.setStatus("web", http.StatusNoContent)
	if _, err := c.fetch(ctx, "web", "secret-key"); !errors.Is(err, errNotManaged) {
		t.Errorf("expected errNotManaged, got %v", err)
	}

	// Unknown name -> 404 -> httpStatusError.
	if _, err := c.fetch(ctx, "missing", "k"); err == nil {
		t.Error("expected error for unknown cert")
	}

	// 200 with a non-PEM body -> parse error.
	m.setStatus("web", 0)
	m.setBundle("web", []byte("this is not pem"))
	if _, err := c.fetch(ctx, "web", "secret-key"); err == nil {
		t.Error("expected a parse error for a non-PEM 200 body")
	}
}

func TestClientFetchNetworkError(t *testing.T) {
	// Port 1 refuses connections, so the HTTP request itself fails.
	c := newClient("http://127.0.0.1:1", "", &http.Client{Timeout: 2 * time.Second})
	if _, err := c.fetch(context.Background(), "web", "k"); err == nil {
		t.Error("expected a network error fetching from a dead address")
	}
}

func TestClientDownloadURL(t *testing.T) {
	c := newClient("https://cw.example.com/", "/certwarden/api/v1/download/privatecertchains/", nil)

	got := c.downloadURL("web")
	want := "https://cw.example.com/certwarden/api/v1/download/privatecertchains/web"
	if got != want {
		t.Errorf("downloadURL = %q, want %q", got, want)
	}

	// Reserved characters in the name must be escaped.
	got = c.downloadURL("my cert/v2")
	want = "https://cw.example.com/certwarden/api/v1/download/privatecertchains/my%20cert%2Fv2"
	if got != want {
		t.Errorf("downloadURL escape = %q, want %q", got, want)
	}
}
