package certwarden

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// retryBackoff is the minimum spacing between fetch attempts for a certificate
// that is not yet loaded or whose last refresh failed, so a persistently
// unreachable Cert Warden is not hammered.
const retryBackoff = time.Minute

// prewarmConcurrency bounds how many certificates are fetched in parallel at
// startup, so a large configuration doesn't open hundreds of simultaneous
// connections to Cert Warden at once.
const prewarmConcurrency = 8

// managedCert holds the configuration and runtime state for a single Cert
// Warden certificate. All mutable fields are guarded by store.mu.
type managedCert struct {
	name             string
	apiKey           string
	explicitSubjects []string // lowercased; when set, overrides SAN-derived matching

	current     *parsedCert
	lastSuccess time.Time
	lastAttempt time.Time
	lastErr     error
}

// subjectsLocked returns the SNI names this certificate should answer for.
// Explicit subjects take precedence; otherwise the leaf's DNS SANs are used.
// Caller must hold store.mu.
func (mc *managedCert) subjectsLocked() []string {
	if len(mc.explicitSubjects) > 0 {
		return mc.explicitSubjects
	}
	if mc.current != nil {
		return mc.current.names
	}
	return nil
}

// wildcardEntry pairs a wildcard SNI pattern (e.g. *.example.com) with the
// certificate that serves it.
type wildcardEntry struct {
	pattern string
	cert    *tls.Certificate
}

// store is the in-memory certificate cache with a background refresher. The
// handshake path (getCertificate) only ever takes a read lock and does a map
// lookup; all network I/O happens in the refresher goroutine.
type store struct {
	client      *client
	logger      *zap.Logger
	certs       []*managedCert
	maxInterval time.Duration // refresh cadence ceiling
	cacheDir    string        // "" disables disk persistence

	mu       sync.RWMutex
	exact    map[string]*tls.Certificate
	wildcard []wildcardEntry

	stopOnce sync.Once
	done     chan struct{}
}

func newStore(c *client, logger *zap.Logger, certs []*managedCert, maxInterval time.Duration, cacheDir string) *store {
	return &store{
		client:      c,
		logger:      logger,
		certs:       certs,
		maxInterval: maxInterval,
		cacheDir:    cacheDir,
		exact:       make(map[string]*tls.Certificate),
		done:        make(chan struct{}),
	}
}

// getCertificate returns the cached certificate for the given SNI server name,
// or nil if none is managed for it. It is safe for concurrent use and does no
// network I/O, so it is safe to call on every TLS handshake.
func (s *store) getCertificate(serverName string) *tls.Certificate {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(serverName), "."))
	if name == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.exact[name]; ok {
		return unexpired(c)
	}
	for _, w := range s.wildcard {
		if certmagic.MatchWildcard(name, w.pattern) {
			return unexpired(w.cert)
		}
	}
	return nil
}

// unexpired returns cert unless it has passed its notAfter, in which case it
// returns nil. Serving an expired certificate would just make the client fail
// the handshake; returning nil lets Caddy fall through to its other certificate
// sources. This covers the case where Cert Warden has been unreachable long
// enough that the last-known certificate has actually expired.
func unexpired(cert *tls.Certificate) *tls.Certificate {
	if cert == nil || cert.Leaf == nil {
		return cert
	}
	if time.Now().After(cert.Leaf.NotAfter) {
		return nil
	}
	return cert
}

// reindexLocked rebuilds the SNI lookup tables from the current certificates.
// Caller must hold s.mu for writing.
func (s *store) reindexLocked() {
	exact := make(map[string]*tls.Certificate, len(s.certs))
	owner := make(map[string]string) // subject -> name of the cert that claimed it
	var wild []wildcardEntry
	for _, mc := range s.certs {
		if mc.current == nil {
			continue
		}
		for _, sub := range mc.subjectsLocked() {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if sub == "" {
				continue
			}
			if strings.HasPrefix(sub, "*.") {
				wild = append(wild, wildcardEntry{pattern: sub, cert: mc.current.tlsCert})
				continue
			}
			if kept, exists := owner[sub]; exists {
				// Two different certificates claim the same exact name; the
				// first configured one wins. Surface it so the operator can
				// fix the overlap. (A cert listing a subject twice is silently
				// deduplicated.)
				if kept != mc.name {
					s.logger.Warn("duplicate certificate subject across certificates; keeping the first configured",
						zap.String("subject", sub),
						zap.String("kept", kept),
						zap.String("ignored", mc.name))
				}
				continue
			}
			exact[sub] = mc.current.tlsCert
			owner[sub] = mc.name
		}
	}
	s.exact = exact
	s.wildcard = wild
}

// prewarm fetches every managed certificate once, concurrently, and returns the
// combined error of any failures. Callers decide whether failures are fatal.
func (s *store) prewarm(ctx context.Context) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, prewarmConcurrency)
	errs := make([]error, len(s.certs))
	for i, mc := range s.certs {
		wg.Add(1)
		sem <- struct{}{} // acquire a slot (blocks past the concurrency limit)
		go func(i int, mc *managedCert) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = s.refreshOne(ctx, mc)
		}(i, mc)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// loadDiskCache seeds the store from previously persisted bundles so that
// certificates are servable immediately at startup, even before the first
// successful fetch (e.g. if Cert Warden is briefly unreachable).
func (s *store) loadDiskCache() {
	if s.cacheDir == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := 0
	for _, mc := range s.certs {
		data, err := os.ReadFile(s.cacheFile(mc.name))
		if err != nil {
			continue
		}
		pc, err := parseBundle(data)
		if err != nil {
			s.logger.Warn("ignoring invalid cached certificate",
				zap.String("name", mc.name), zap.Error(err))
			continue
		}
		mc.current = pc
		loaded++
	}
	if loaded > 0 {
		s.reindexLocked()
		s.logger.Info("loaded certificates from disk cache", zap.Int("count", loaded))
	}
}

// run is the background refresher loop. It exits when ctx is cancelled or stop
// is called.
func (s *store) run(ctx context.Context) {
	tick := s.maxInterval
	if tick > time.Minute || tick <= 0 {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			s.refreshDue(ctx)
		}
	}
}

// refreshDue refreshes every certificate that is currently due.
func (s *store) refreshDue(ctx context.Context) {
	now := time.Now()
	for _, mc := range s.certs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if s.isDue(mc, now) {
			_ = s.refreshOne(ctx, mc)
		}
	}
}

// isDue reports whether a certificate should be refreshed now.
func (s *store) isDue(mc *managedCert, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Never attempt faster than the retry backoff.
	if !mc.lastAttempt.IsZero() && now.Sub(mc.lastAttempt) < retryBackoff {
		return false
	}
	if mc.current == nil {
		return true // not loaded yet; keep trying
	}
	if mc.lastErr != nil {
		return true // last attempt failed; retry (backoff already enforced above)
	}
	// Refresh at two-thirds of the certificate's lifetime, or at the configured
	// interval ceiling, whichever comes first. This both stays ahead of expiry
	// and promptly picks up rotations Cert Warden performs early.
	renewAt := mc.current.notAfter.Add(-mc.current.lifetime / 3)
	intervalAt := mc.lastSuccess.Add(s.maxInterval)
	dueAt := renewAt
	if intervalAt.Before(dueAt) {
		dueAt = intervalAt
	}
	return !now.Before(dueAt)
}

// refreshOne fetches a single certificate and swaps it into the cache on
// success. On failure the previously cached certificate (if any) is retained.
func (s *store) refreshOne(ctx context.Context, mc *managedCert) error {
	pc, err := s.client.fetch(ctx, mc.name, mc.apiKey)
	now := time.Now()

	s.mu.Lock()
	mc.lastAttempt = now
	if err != nil {
		mc.lastErr = err
		s.mu.Unlock()
		if errors.Is(err, errNotManaged) {
			s.logger.Warn("cert warden reports certificate not managed",
				zap.String("name", mc.name))
		} else {
			s.logger.Error("failed to refresh certificate",
				zap.String("name", mc.name), zap.Error(err))
		}
		return err
	}
	mc.current = pc
	mc.lastSuccess = now
	mc.lastErr = nil
	s.reindexLocked()
	s.mu.Unlock()

	s.logger.Info("refreshed certificate",
		zap.String("name", mc.name),
		zap.Strings("subjects", pc.names),
		zap.Time("not_after", pc.notAfter))

	if s.cacheDir != "" {
		if err := s.persist(mc.name, pc.pem); err != nil {
			s.logger.Warn("failed to persist certificate to disk cache",
				zap.String("name", mc.name), zap.Error(err))
		}
	}
	return nil
}

// stop signals the refresher loop to exit. Safe to call more than once.
func (s *store) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

// cacheFile returns the on-disk path for a certificate's persisted bundle. The
// name is sanitized and suffixed with a short hash of the original name to keep
// filenames safe and collision-free.
func (s *store) cacheFile(name string) string {
	sum := sha256.Sum256([]byte(name))
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
	return filepath.Join(s.cacheDir, safe+"-"+hex.EncodeToString(sum[:4])+".pem")
}

// persist atomically writes a bundle to the disk cache with 0600 permissions.
func (s *store) persist(name string, bundle []byte) error {
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return err
	}
	final := s.cacheFile(name)
	tmp, err := os.CreateTemp(s.cacheDir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(bundle); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, final)
}
