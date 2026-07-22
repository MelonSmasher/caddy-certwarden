package certwarden

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func testClient(m *mockCW) *client {
	return newClient(m.url(), "", &http.Client{Timeout: 5 * time.Second})
}

func servedSANs(cert *tls.Certificate) []string {
	if cert == nil || cert.Leaf == nil {
		return nil
	}
	return cert.Leaf.DNSNames
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// TestStoreCachesAndServes is the central guarantee: after one prewarm fetch,
// any number of handshakes are served from memory with no further fetches.
func TestStoreCachesAndServes(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"a.example.com", "b.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour)))

	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	if got := m.requests(); got != 1 {
		t.Fatalf("prewarm made %d requests, want 1", got)
	}

	if cert := s.getCertificate("a.example.com"); cert == nil {
		t.Fatal("expected certificate for a.example.com")
	}
	if cert := s.getCertificate("B.EXAMPLE.COM"); cert == nil {
		t.Fatal("expected case-insensitive match for b.example.com")
	}

	// Hammer the handshake path; the fetch count must not move.
	for i := 0; i < 5000; i++ {
		if cert := s.getCertificate("a.example.com"); cert == nil {
			t.Fatal("cache miss during hammer loop")
		}
	}
	if got := m.requests(); got != 1 {
		t.Fatalf("handshakes triggered %d fetches, want 1 (no per-handshake fetching)", got)
	}
}

func TestStoreWildcard(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("wild", makeBundlePEM(t, []string{"*.apps.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "wild", apiKey: "k"}}, 12*time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	if cert := s.getCertificate("foo.apps.example.com"); cert == nil {
		t.Fatal("expected wildcard match for foo.apps.example.com")
	}
	if cert := s.getCertificate("apps.example.com"); cert != nil {
		t.Fatal("wildcard must not match the bare parent domain")
	}
	if cert := s.getCertificate("a.b.apps.example.com"); cert != nil {
		t.Fatal("single-label wildcard must not match a multi-label subdomain")
	}
}

func TestStoreUnknownPassthrough(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"known.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, "")
	_ = s.prewarm(context.Background())

	if cert := s.getCertificate("unknown.example.com"); cert != nil {
		t.Fatal("expected nil (pass-through) for an unmanaged name")
	}
	if cert := s.getCertificate(""); cert != nil {
		t.Fatal("expected nil for empty server name")
	}
}

func TestStoreExpiredCertPassthrough(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	// An already-expired certificate: Cert Warden stayed unreachable past its
	// notAfter and we only have the stale copy. It must not be served.
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour)))
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, "")
	_ = s.prewarm(context.Background())

	if cert := s.getCertificate("web.example.com"); cert != nil {
		t.Fatal("expected nil (pass-through) for an expired certificate, not the stale cert")
	}
}

func TestStoreDuplicateSubjectWarns(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	m := newMockCW(t)
	now := time.Now()
	// Two different Cert Warden certs both claim web.example.com.
	m.setBundle("a", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	m.setBundle("b", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	s := newStore(testClient(m), zap.New(core),
		[]*managedCert{{name: "a", apiKey: "k"}, {name: "b", apiKey: "k"}}, 12*time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}

	// The name is still served (first configured cert wins).
	if s.getCertificate("web.example.com") == nil {
		t.Fatal("expected the first cert to be served despite the conflict")
	}
	// And the conflict was surfaced.
	if logs.FilterMessageSnippet("duplicate certificate subject").Len() == 0 {
		t.Error("expected a duplicate-subject warning to be logged")
	}
}

func TestStoreExplicitSubjectsOverride(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	// Cert's SAN is san.example.com, but we override to serve it for alias.example.com.
	m.setBundle("web", makeBundlePEM(t, []string{"san.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	s := newStore(testClient(m), zap.NewNop(),
		[]*managedCert{{name: "web", apiKey: "k", explicitSubjects: []string{"alias.example.com"}}}, 12*time.Hour, "")
	_ = s.prewarm(context.Background())

	if cert := s.getCertificate("alias.example.com"); cert == nil {
		t.Fatal("expected override subject alias.example.com to be served")
	}
	if cert := s.getCertificate("san.example.com"); cert != nil {
		t.Fatal("explicit subjects should override SAN-derived matching")
	}
}

func TestStoreRefreshSwaps(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com", "v1.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	mc := &managedCert{name: "web", apiKey: "k"}
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{mc}, 12*time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	if got := servedSANs(s.getCertificate("web.example.com")); !contains(got, "v1.example.com") {
		t.Fatalf("expected v1 cert, got SANs %v", got)
	}

	// New bundle at Cert Warden; force a refresh.
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com", "v2.example.com"}, now.Add(-time.Hour), now.Add(48*time.Hour)))
	if err := s.refreshOne(context.Background(), mc); err != nil {
		t.Fatalf("refreshOne: %v", err)
	}
	if got := servedSANs(s.getCertificate("web.example.com")); !contains(got, "v2.example.com") {
		t.Fatalf("expected v2 cert after refresh, got SANs %v", got)
	}
}

func TestStoreRefreshFailureKeepsStale(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	mc := &managedCert{name: "web", apiKey: "k"}
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{mc}, 12*time.Hour, "")
	_ = s.prewarm(context.Background())

	// Cert Warden now errors; the previously cached cert must still be served.
	m.setStatus("web", http.StatusInternalServerError)
	if err := s.refreshOne(context.Background(), mc); err == nil {
		t.Fatal("expected refresh error")
	}
	if cert := s.getCertificate("web.example.com"); cert == nil {
		t.Fatal("expected stale cert to remain served after a failed refresh")
	}
}

func TestStoreNotManaged204(t *testing.T) {
	m := newMockCW(t)
	m.setStatus("web", http.StatusNoContent)
	mc := &managedCert{name: "web", apiKey: "k"}
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{mc}, 12*time.Hour, "")
	// prewarm returns an error (not managed), and nothing is served.
	if err := s.prewarm(context.Background()); err == nil {
		t.Fatal("expected prewarm error for 204")
	}
	if cert := s.getCertificate("web.example.com"); cert != nil {
		t.Fatal("expected no certificate for a 204 (not managed) response")
	}
}

func TestStoreDiskPersistence(t *testing.T) {
	dir := t.TempDir()
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))

	// First store fetches and persists to disk.
	s1 := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, dir)
	if err := s1.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}

	// Second store loads purely from disk with Cert Warden unreachable.
	m.setStatus("web", http.StatusInternalServerError)
	s2 := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, 12*time.Hour, dir)
	s2.loadDiskCache()
	if cert := s2.getCertificate("web.example.com"); cert == nil {
		t.Fatal("expected cert served from disk cache while backend is down")
	}
}

func TestIsDue(t *testing.T) {
	s := newStore(nil, zap.NewNop(), nil, 12*time.Hour, "")
	now := time.Now()

	// Never loaded -> due.
	if !s.isDue(&managedCert{}, now) {
		t.Error("uninitialized cert should be due")
	}
	// Loaded, fresh, recently fetched -> not due.
	fresh := &managedCert{
		current:     &parsedCert{notAfter: now.Add(80 * 24 * time.Hour), lifetime: 90 * 24 * time.Hour},
		lastSuccess: now,
	}
	if s.isDue(fresh, now) {
		t.Error("fresh cert refreshed just now should not be due")
	}
	// Past two-thirds of lifetime -> due.
	old := &managedCert{
		current:     &parsedCert{notAfter: now.Add(10 * 24 * time.Hour), lifetime: 90 * 24 * time.Hour},
		lastSuccess: now.Add(-70 * 24 * time.Hour),
	}
	if !s.isDue(old, now) {
		t.Error("cert past 2/3 lifetime should be due")
	}
	// Recent failed attempt -> backoff, not due yet.
	failing := &managedCert{lastAttempt: now.Add(-time.Second), lastErr: errNotManaged}
	if s.isDue(failing, now) {
		t.Error("cert within retry backoff should not be due")
	}
	// Loaded but last refresh errored, past the backoff -> due (retry).
	staleErr := &managedCert{
		current:     &parsedCert{notAfter: now.Add(50 * 24 * time.Hour), lifetime: 90 * 24 * time.Hour},
		lastErr:     errNotManaged,
		lastAttempt: now.Add(-2 * time.Minute),
	}
	if !s.isDue(staleErr, now) {
		t.Error("stale cert whose last refresh failed (past backoff) should be due")
	}
}

func TestRefreshDueLoadsColdCert(t *testing.T) {
	m := newMockCW(t)
	m.setStatus("web", http.StatusInternalServerError) // initial fetch fails
	mc := &managedCert{name: "web", apiKey: "k"}
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{mc}, 12*time.Hour, "")
	_ = s.prewarm(context.Background())
	if s.getCertificate("web.example.com") != nil {
		t.Fatal("expected no cert after the failed initial fetch")
	}

	// Cert Warden recovers; clear the backoff so the next sweep is due.
	now := time.Now()
	m.setStatus("web", 0)
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	s.mu.Lock()
	mc.lastAttempt = time.Time{}
	s.mu.Unlock()

	s.refreshDue(context.Background())
	if s.getCertificate("web.example.com") == nil {
		t.Fatal("expected the cold cert to load on the next due sweep")
	}
}

func TestRunRefreshesInBackground(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	// Tiny interval so run() ticks quickly; no prewarm, so run() does the load.
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{{name: "web", apiKey: "k"}}, time.Millisecond, "")

	ctx, cancel := context.WithCancel(context.Background())
	go s.run(ctx)
	defer func() { cancel(); s.stop() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.getCertificate("web.example.com") != nil {
			return // background refresher loaded it
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("run() did not refresh the certificate in the background")
}

func TestLoadDiskCacheInvalidFile(t *testing.T) {
	dir := t.TempDir()
	// "web" has an invalid cache file; "nofile" has none at all.
	s := newStore(nil, zap.NewNop(), []*managedCert{{name: "web"}, {name: "nofile"}}, time.Hour, dir)
	if err := os.WriteFile(s.cacheFile("web"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.loadDiskCache() // must skip both (warn on the invalid one), not panic or load
	if s.getCertificate("web.example.com") != nil {
		t.Fatal("expected nothing loaded from an invalid cache file")
	}
}

func TestPersistError(t *testing.T) {
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// cacheDir sits under a regular file, so MkdirAll must fail.
	s := newStore(nil, zap.NewNop(), nil, time.Hour, filepath.Join(fileAsDir, "sub"))
	if err := s.persist("web", []byte("data")); err == nil {
		t.Error("expected persist to error when the cache dir cannot be created")
	}
}

func TestSubjectsLocked(t *testing.T) {
	// No current certificate and no explicit subjects -> nil.
	if got := (&managedCert{}).subjectsLocked(); got != nil {
		t.Errorf("expected nil subjects, got %v", got)
	}
}

func TestReindexSelfDuplicate(t *testing.T) {
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("a", makeBundlePEM(t, []string{"whatever.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	// The same explicit subject listed twice on one cert is silently deduped.
	s := newStore(testClient(m), zap.NewNop(),
		[]*managedCert{{name: "a", apiKey: "k", explicitSubjects: []string{"dup.example.com", "dup.example.com"}}},
		time.Hour, "")
	if err := s.prewarm(context.Background()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	if s.getCertificate("dup.example.com") == nil {
		t.Fatal("expected the deduplicated subject to be served")
	}
}

func TestRefreshOnePersistError(t *testing.T) {
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMockCW(t)
	now := time.Now()
	m.setBundle("web", makeBundlePEM(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour)))
	mc := &managedCert{name: "web", apiKey: "k"}
	// cacheDir sits under a regular file, so the disk write fails while the
	// refresh itself succeeds: the cert is cached in memory and a warning logged.
	s := newStore(testClient(m), zap.NewNop(), []*managedCert{mc}, time.Hour, filepath.Join(fileAsDir, "sub"))
	if err := s.refreshOne(context.Background(), mc); err != nil {
		t.Fatalf("refreshOne should succeed even when the disk cache write fails: %v", err)
	}
	if s.getCertificate("web.example.com") == nil {
		t.Fatal("cert should be cached in memory despite the persist failure")
	}
}

func TestUnexpired(t *testing.T) {
	if unexpired(nil) != nil {
		t.Error("unexpired(nil) should be nil")
	}
	noLeaf := &tls.Certificate{} // Leaf is nil
	if unexpired(noLeaf) != noLeaf {
		t.Error("unexpired with a nil Leaf should return the certificate unchanged")
	}
}

func TestRefreshDueCanceled(t *testing.T) {
	// A cancelled context must make refreshDue return immediately, before it
	// touches the (nil) client.
	s := newStore(nil, zap.NewNop(), []*managedCert{{name: "web"}}, time.Hour, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.refreshDue(ctx)
}

func TestCacheFileSanitizes(t *testing.T) {
	s := newStore(nil, zap.NewNop(), nil, time.Hour, "/cache")
	got := s.cacheFile("weird name/../x")
	if strings.ContainsAny(filepath.Base(got), "/ ") {
		t.Errorf("cacheFile did not sanitize the name: %q", got)
	}
}

func TestRunStops(t *testing.T) {
	s := newStore(nil, zap.NewNop(), nil, time.Hour, "")
	done := make(chan struct{})
	go func() {
		s.run(context.Background())
		close(done)
	}()
	s.stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not exit after stop()")
	}
	// stop must be safe to call again.
	s.stop()
}
