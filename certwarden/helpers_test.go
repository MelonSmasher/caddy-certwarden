package certwarden

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeBundlePEM generates a self-signed certificate for the given DNS SANs and
// validity window, returning a Cert-Warden-style "private key + certificate"
// PEM bundle (one PRIVATE KEY block followed by one CERTIFICATE block).
func makeBundlePEM(t *testing.T, sans []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	cn := ""
	if len(sans) > 0 {
		cn = sans[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              sans,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encoding cert: %v", err)
	}
	return buf.Bytes()
}

// mockCW is a stand-in Cert Warden download endpoint that counts requests, so
// tests can assert how many times the plugin actually fetched.
type mockCW struct {
	srv *httptest.Server

	count int64 // atomic

	mu      sync.Mutex
	bundles map[string][]byte
	keys    map[string]string // required X-API-Key per cert name ("" = no check)
	status  map[string]int    // forced status code per cert name (0 = normal)
}

func newMockCW(t *testing.T) *mockCW {
	t.Helper()
	m := &mockCW{
		bundles: make(map[string][]byte),
		keys:    make(map[string]string),
		status:  make(map[string]int),
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockCW) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.count, 1)
	name := path.Base(r.URL.Path)

	m.mu.Lock()
	bundle, ok := m.bundles[name]
	wantKey := m.keys[name]
	forced := m.status[name]
	m.mu.Unlock()

	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if wantKey != "" && r.Header.Get("X-API-Key") != wantKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(bundle)
}

func (m *mockCW) setBundle(name string, bundle []byte) {
	m.mu.Lock()
	m.bundles[name] = bundle
	m.mu.Unlock()
}

func (m *mockCW) setKey(name, key string) {
	m.mu.Lock()
	m.keys[name] = key
	m.mu.Unlock()
}

func (m *mockCW) setStatus(name string, code int) {
	m.mu.Lock()
	m.status[name] = code
	m.mu.Unlock()
}

func (m *mockCW) requests() int64 { return atomic.LoadInt64(&m.count) }

func (m *mockCW) url() string { return m.srv.URL }

// certBlocksOnly returns the input bundle with only its CERTIFICATE blocks.
func certBlocksOnly(t *testing.T, bundle []byte) []byte {
	t.Helper()
	return filterPEM(t, bundle, "CERTIFICATE")
}

// keyBlocksOnly returns the input bundle with only its PRIVATE KEY blocks.
func keyBlocksOnly(t *testing.T, bundle []byte) []byte {
	t.Helper()
	return filterPEM(t, bundle, "PRIVATE KEY")
}

func filterPEM(t *testing.T, bundle []byte, keep string) []byte {
	t.Helper()
	var out bytes.Buffer
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == keep {
			if err := pem.Encode(&out, block); err != nil {
				t.Fatalf("re-encoding %s: %v", keep, err)
			}
		}
	}
	return out.Bytes()
}
