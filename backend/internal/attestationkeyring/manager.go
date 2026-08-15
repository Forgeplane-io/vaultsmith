package attestationkeyring

import (
	"context"
	"crypto/sha256"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
)

// Logger is the minimal logging seam used for generic reload events.
type Logger interface {
	Printf(string, ...any)
}

// Manager owns the current immutable keyring snapshot and its fixed polling
// reload loop. It is safe for concurrent signing, resolution, discovery, and
// reload operations.
type Manager struct {
	path   string
	issuer string
	logger Logger

	current         atomic.Pointer[Snapshot]
	reloadSuccesses atomic.Uint64
	reloadFailures  atomic.Uint64

	mu       sync.Mutex
	reloadMu sync.Mutex
	started  bool
	closed   bool
	stop     chan struct{}
	done     chan struct{}
}

var _ attestation.KeyResolver = (*Manager)(nil)

// NewManager validates and loads the initial keyring. A missing or invalid
// initial file returns before a manager is made available to callers.
func NewManager(path, issuer string) (*Manager, error) {
	return newManager(path, issuer, log.Default())
}

// NewManagerWithLogger is the test and embedding seam for generic lifecycle
// logging. The logger must not be used to print input, claims, or key data.
func NewManagerWithLogger(path, issuer string, logger Logger) (*Manager, error) {
	if logger == nil {
		logger = log.Default()
	}
	return newManager(path, issuer, logger)
}

func newManager(path, issuer string, logger Logger) (*Manager, error) {
	if path == "" {
		return nil, ErrKeyringUnavailable
	}
	snapshot, err := LoadFile(path, issuer)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		path:   path,
		issuer: snapshot.issuer,
		logger: logger,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	manager.current.Store(snapshot)
	return manager, nil
}

// LoadFile reads and validates one complete bounded keyring file.
func LoadFile(path, issuer string) (*Snapshot, error) {
	if path == "" {
		return nil, ErrKeyringUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrKeyringUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrKeyringUnavailable
	}
	if len(data) > MaxFileBytes {
		return nil, ErrKeyringTooLarge
	}
	return Parse(data, issuer)
}

// Snapshot returns the current immutable state. The pointer and all of its
// fields are safe to share because Snapshot exposes no mutable internals.
func (m *Manager) Snapshot() *Snapshot {
	if m == nil {
		return nil
	}
	return m.current.Load()
}

// Issuer returns the canonical local issuer configured for this manager.
func (m *Manager) Issuer() string {
	if m == nil {
		return ""
	}
	return m.issuer
}

// Ready reports whether a valid snapshot is available and the manager is not
// closed.
func (m *Manager) Ready() bool {
	if m == nil || m.current.Load() == nil {
		return false
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	return !closed
}

// ReloadFailureCount returns the bounded in-process count of rejected reloads.
func (m *Manager) ReloadFailureCount() uint64 {
	if m == nil {
		return 0
	}
	return m.reloadFailures.Load()
}

// ReloadSuccessCount returns the bounded in-process count of accepted
// replacements. The initial load is represented by the loaded gauge, not a
// reload event.
func (m *Manager) ReloadSuccessCount() uint64 {
	if m == nil {
		return 0
	}
	return m.reloadSuccesses.Load()
}

// Reload reads, validates, and atomically swaps a changed keyring. A failed
// replacement leaves the prior snapshot active and Ready.
func (m *Manager) Reload() error {
	if m == nil {
		return ErrNotReady
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrClosed
	}

	data, err := readBoundedFile(m.path)
	if err != nil {
		return m.rejectReload(err)
	}
	hash := sha256.Sum256(data)
	current := m.current.Load()
	if current != nil && current.contentHash == hash {
		return nil
	}
	next, err := Parse(data, m.issuer)
	if err != nil {
		return m.rejectReload(err)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	m.current.Store(next)
	m.reloadSuccesses.Add(1)
	m.mu.Unlock()
	return nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrKeyringUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrKeyringUnavailable
	}
	if len(data) > MaxFileBytes {
		return nil, ErrKeyringTooLarge
	}
	return data, nil
}

func (m *Manager) rejectReload(err error) error {
	m.reloadFailures.Add(1)
	if m.logger != nil {
		m.logger.Printf("attestation keyring reload rejected")
	}
	return err
}

// Start begins the fixed five-second reload poller. Calling Start more than
// once is harmless. A canceled context stops the poller without a goroutine
// leak.
func (m *Manager) Start(ctx context.Context) error {
	return m.start(ctx, ReloadInterval)
}

func (m *Manager) start(ctx context.Context, interval time.Duration) error {
	if m == nil {
		return ErrNotReady
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if interval <= 0 {
		return ErrInvalidKeyring
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	stop := m.stop
	done := m.done
	m.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				_ = m.Reload()
			}
		}
	}()
	return nil
}

// Close stops the reload poller. It does not erase a snapshot that may still
// be held by an in-flight operation.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stop)
	}
	started := m.started
	done := m.done
	m.mu.Unlock()
	if started {
		<-done
	}
	return nil
}

// Resolve forwards issuer-bound resolution through one current snapshot.
func (m *Manager) Resolve(issuer, kid string) (attestation.KeyResolution, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return attestation.KeyResolution{}, err
	}
	return snapshot.Resolve(issuer, kid)
}

// Sign forwards v1 signing through one current snapshot.
func (m *Manager) Sign(claims attestation.RotationClaims) (attestation.Signed, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return attestation.Signed{}, err
	}
	return snapshot.Sign(claims)
}

// Metadata returns a detached discovery model from one current snapshot.
func (m *Manager) Metadata() (Metadata, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return Metadata{}, err
	}
	return snapshot.Metadata(), nil
}

// JWKS returns a detached public-only discovery model from one current
// snapshot.
func (m *Manager) JWKS() (JWKS, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return JWKS{}, err
	}
	return snapshot.JWKS(), nil
}

// MetadataJSON returns deterministic discovery bytes from one current
// snapshot.
func (m *Manager) MetadataJSON() ([]byte, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return nil, err
	}
	return snapshot.MetadataJSON()
}

// JWKSJSON returns deterministic public discovery bytes from one current
// snapshot.
func (m *Manager) JWKSJSON() ([]byte, error) {
	snapshot, err := m.readySnapshot()
	if err != nil {
		return nil, err
	}
	return snapshot.JWKSJSON()
}

func (m *Manager) readySnapshot() (*Snapshot, error) {
	if m == nil {
		return nil, ErrNotReady
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	snapshot := m.current.Load()
	if snapshot == nil {
		return nil, ErrNotReady
	}
	return snapshot, nil
}
