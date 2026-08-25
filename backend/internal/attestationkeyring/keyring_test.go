package attestationkeyring

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
)

const testIssuer = "https://vaultsmith.example.test"

type testKey struct {
	id          string
	state       KeyState
	seed        []byte
	privateSeed []byte
}

func makeTestKey(id string, state KeyState, seedByte byte) testKey {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateSeed := []byte(nil)
	if state == StateActive {
		privateSeed = seed
	}
	return testKey{id: id, state: state, seed: seed, privateSeed: privateSeed}
}

func makeKeyringJSON(active string, entries ...testKey) []byte {
	type wireKey struct {
		ID         string   `json:"id"`
		State      KeyState `json:"state"`
		PublicKey  string   `json:"publicKey"`
		PrivateKey string   `json:"privateKey,omitempty"`
	}
	keys := make([]wireKey, 0, len(entries))
	for _, entry := range entries {
		privateKey := ""
		if entry.privateSeed != nil {
			privateKey = base64.RawURLEncoding.EncodeToString(entry.privateSeed)
		}
		publicKey := ed25519.NewKeyFromSeed(entry.seed).Public().(ed25519.PublicKey)
		keys = append(keys, wireKey{
			ID:         entry.id,
			State:      entry.state,
			PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
			PrivateKey: privateKey,
		})
	}
	raw, err := json.Marshal(struct {
		Version int       `json:"version"`
		Active  string    `json:"active"`
		Keys    []wireKey `json:"keys"`
	}{Version: 1, Active: active, Keys: keys})
	if err != nil {
		panic(err)
	}
	return raw
}

func writeKeyring(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceKeyring(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func testClaims(issuer string) attestation.RotationClaims {
	return attestation.RotationClaims{
		Version:              attestation.SupportedVersion,
		Issuer:               issuer,
		IssuedAt:             "2026-08-15T00:00:00Z",
		Operation:            "rotate",
		SourceProfileID:      "source",
		DestinationProfileID: "destination",
		Input:                attestation.Digest{Algorithm: "sha-256", Value: strings.Repeat("a", 64)},
		Output:               attestation.Digest{Algorithm: "sha-256", Value: strings.Repeat("b", 64)},
	}
}

func assertInvalid(t *testing.T, data []byte) {
	t.Helper()
	if _, err := Parse(data, testIssuer); !errors.Is(err, ErrInvalidKeyring) && !errors.Is(err, ErrKeyringTooLarge) {
		t.Fatalf("Parse() error = %v, want invalid keyring", err)
	}
}

func TestLoadFilePreservesBoundedReadErrors(t *testing.T) {
	if _, err := LoadFile("", testIssuer); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("empty path error = %v, want ErrKeyringUnavailable", err)
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"), testIssuer); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("missing file error = %v, want ErrKeyringUnavailable", err)
	}

	active := makeTestKey("rotation-2026-08", StateActive, 1)
	validPath := writeKeyring(t, makeKeyringJSON(active.id, active))
	if _, err := LoadFile(validPath, testIssuer); err != nil {
		t.Fatalf("valid file error = %v", err)
	}

	invalidPath := writeKeyring(t, []byte(`{"version":1,"active":"bad","keys":[]}`))
	if _, err := LoadFile(invalidPath, testIssuer); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("malformed file error = %v, want ErrInvalidKeyring", err)
	}

	exactLimitPath := writeKeyring(t, bytes.Repeat([]byte{'x'}, MaxFileBytes))
	if _, err := LoadFile(exactLimitPath, testIssuer); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("exact-limit file error = %v, want ErrInvalidKeyring after bounded read", err)
	}

	overLimitPath := writeKeyring(t, bytes.Repeat([]byte{'x'}, MaxFileBytes+1))
	if _, err := LoadFile(overLimitPath, testIssuer); !errors.Is(err, ErrKeyringTooLarge) {
		t.Fatalf("over-limit file error = %v, want ErrKeyringTooLarge", err)
	}
}

func TestParseValidatesOneActiveKeyAndMaterial(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	snapshot, err := Parse(makeKeyringJSON(active.id, active), testIssuer)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if snapshot.ActiveKID() != active.id || snapshot.Issuer() != testIssuer {
		t.Fatalf("snapshot identity = %q/%q", snapshot.ActiveKID(), snapshot.Issuer())
	}
	if _, err := snapshot.Resolve(testIssuer, active.id); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestParseRejectsSchemaAndLifecycleViolations(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	retired := makeTestKey("rotation-2026-07", StateRetired, 2)
	tests := []struct {
		name string
		data []byte
	}{
		{"unsupported version", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`"version":1`), []byte(`"version":2`), 1)},
		{"non-integer version", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`"version":1`), []byte(`"version":1.0`), 1)},
		{"duplicate top-level member", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`"version":1,`), []byte(`"version":1,"version":1,`), 1)},
		{"unknown top-level member", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`{"version"`), []byte(`{"revoked":[],"version"`), 1)},
		{"duplicate entry member", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`"id":"rotation-2026-08",`), []byte(`"id":"rotation-2026-08","id":"rotation-2026-08",`), 1)},
		{"unknown entry member", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`{"id"`), []byte(`{"extra":true,"id"`), 1)},
		{"no active key", makeKeyringJSON(retired.id, retired)},
		{"two active keys", makeKeyringJSON(active.id, active, makeTestKey("rotation-2026-09", StateActive, 3))},
		{"active field mismatch", makeKeyringJSON("rotation-2026-09", active)},
		{"duplicate IDs", makeKeyringJSON(active.id, active, active)},
		{"invalid ID grammar", makeKeyringJSON("rotation/2026", makeTestKey("rotation/2026", StateActive, 1))},
		{"invalid Unicode", bytes.Replace(makeKeyringJSON(active.id, active), []byte(`"active":"rotation-2026-08"`), []byte(`"active":"\ud800"`), 1)},
		{"retired private key", makeKeyringJSON(active.id, active, retiredWithPrivate(retired))},
		{"revoked private key", makeKeyringJSON(active.id, active, revokedWithPrivate(makeTestKey("rotation-2026-07", StateRevoked, 2)))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertInvalid(t, tt.data) })
	}
}

func retiredWithPrivate(key testKey) testKey {
	key.privateSeed = key.seed
	return key
}

func revokedWithPrivate(key testKey) testKey {
	key.privateSeed = key.seed
	return key
}

func TestParseRejectsKeyMaterialAndResourceLimits(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	mismatched := makeTestKey("rotation-2026-08", StateActive, 1)
	mismatched.privateSeed = bytes.Repeat([]byte{9}, ed25519.SeedSize)
	assertInvalid(t, makeKeyringJSON(active.id, mismatched))

	publicKey := ed25519.NewKeyFromSeed(active.seed).Public().(ed25519.PublicKey)
	publicText := base64.RawURLEncoding.EncodeToString(publicKey)
	shortPublic := base64.RawURLEncoding.EncodeToString([]byte{1})
	assertInvalid(t, bytes.Replace(makeKeyringJSON(active.id, active), []byte(publicText), []byte(shortPublic), 1))
	assertInvalid(t, bytes.Replace(makeKeyringJSON(active.id, active), []byte(publicText), []byte("!"+publicText[1:]), 1))
	privateText := base64.RawURLEncoding.EncodeToString(active.seed)
	shortPrivate := base64.RawURLEncoding.EncodeToString([]byte{1})
	assertInvalid(t, bytes.Replace(makeKeyringJSON(active.id, active), []byte(privateText), []byte(shortPrivate), 1))

	padded := makeKeyringJSON(active.id, active)
	padded = bytes.Replace(padded, []byte(`"publicKey":"`), []byte(`"publicKey":"=`), 1)
	assertInvalid(t, padded)

	if _, err := Parse(bytes.Repeat([]byte{'x'}, MaxFileBytes+1), testIssuer); !errors.Is(err, ErrKeyringTooLarge) {
		t.Fatalf("oversized Parse() error = %v, want ErrKeyringTooLarge", err)
	}

	entries := make([]testKey, 0, MaxEntries+1)
	entries = append(entries, active)
	for index := 0; index < MaxEntries; index++ {
		entries = append(entries, makeTestKey(fmt.Sprintf("retired-%03d", index), StateRetired, byte(index+2)))
	}
	assertInvalid(t, makeKeyringJSON(active.id, entries...))
}

func TestSnapshotSignsAndResolvesIssuerBoundKeys(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	retired := makeTestKey("rotation-2026-07", StateRetired, 2)
	snapshot, err := Parse(makeKeyringJSON(active.id, active, retired), testIssuer)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	claims := testClaims(testIssuer)
	signed, err := snapshot.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	verified, err := attestation.Verify(signed, attestation.VerifyOptions{
		ExpectedIssuer: testIssuer,
		Resolver:       snapshot,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Issuer != testIssuer {
		t.Fatalf("verified issuer = %q", verified.Issuer)
	}
	if _, err := snapshot.Resolve("https://other.example.test", active.id); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("wrong issuer Resolve() error = %v", err)
	}
	if _, err := snapshot.Resolve(testIssuer, "missing"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown Resolve() error = %v", err)
	}
	if _, err := snapshot.Sign(testClaims("https://other.example.test")); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("wrong issuer Sign() error = %v", err)
	}
}

func TestDiscoveryIsDeterministicAndPublicOnly(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	retired := makeTestKey("rotation-2026-07", StateRetired, 2)
	revoked := makeTestKey("rotation-2026-06", StateRevoked, 3)
	snapshot, err := Parse(makeKeyringJSON(active.id, revoked, active, retired), testIssuer)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	metadataA, err := snapshot.MetadataJSON()
	if err != nil {
		t.Fatalf("MetadataJSON() error = %v", err)
	}
	metadataB, err := snapshot.MetadataJSON()
	if err != nil || !bytes.Equal(metadataA, metadataB) {
		t.Fatalf("metadata is not deterministic: %q / %q / %v", metadataA, metadataB, err)
	}
	jwks, err := snapshot.JWKSJSON()
	if err != nil {
		t.Fatalf("JWKSJSON() error = %v", err)
	}
	if bytes.Contains(jwks, []byte(`rotation-2026-06`)) || bytes.Contains(jwks, []byte(`privateKey`)) {
		t.Fatalf("JWKS exposes revoked or private material: %s", jwks)
	}
	if !bytes.Contains(metadataA, []byte(`"revokedKids":["rotation-2026-06"]`)) {
		t.Fatalf("metadata does not list revoked kid: %s", metadataA)
	}
	if !bytes.Contains(jwks, []byte(`"keys"`)) || !bytes.Contains(jwks, []byte(`"alg":"Ed25519"`)) {
		t.Fatalf("JWKS is missing required public fields: %s", jwks)
	}
	if strings.Index(string(jwks), "rotation-2026-07") > strings.Index(string(jwks), "rotation-2026-08") {
		t.Fatalf("JWKS keys are not sorted by kid: %s", jwks)
	}
	metadata := snapshot.Metadata()
	metadata.RevokedKids[0] = "mutated"
	if snapshot.Metadata().RevokedKids[0] != "rotation-2026-06" {
		t.Fatal("metadata returned a mutable snapshot slice")
	}
	model := snapshot.JWKS()
	model.Keys[0].Kid = "mutated"
	if snapshot.JWKS().Keys[0].Kid != "rotation-2026-07" {
		t.Fatal("JWKS returned a mutable snapshot slice")
	}
}

func TestManagerReloadPreservesSnapshotAndHistoricalVerification(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	retired := makeTestKey("rotation-2026-07", StateRetired, 2)
	path := writeKeyring(t, makeKeyringJSON(active.id, active, retired))
	var logs bytes.Buffer
	manager, err := NewManagerWithLogger(path, testIssuer, logBuffer{&logs})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	oldSigned, err := manager.Sign(testClaims(testIssuer))
	if err != nil {
		t.Fatalf("initial Sign() error = %v", err)
	}
	initialSnapshot := manager.Snapshot()
	if err := manager.Reload(); err != nil {
		t.Fatalf("unchanged Reload() error = %v", err)
	}
	if manager.Snapshot() != initialSnapshot {
		t.Fatal("unchanged content hash rebuilt the snapshot")
	}
	bad := []byte(`{"version":1,"active":"bad","keys":[]}`)
	replaceKeyring(t, path, bad)
	if err := manager.Reload(); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("invalid Reload() error = %v", err)
	}
	if manager.ReloadFailureCount() != 1 || manager.ReloadSuccessCount() != 0 || !manager.Ready() || manager.Snapshot().ActiveKID() != active.id {
		t.Fatalf("failed reload changed readiness/snapshot: failures=%d successes=%d ready=%v active=%q", manager.ReloadFailureCount(), manager.ReloadSuccessCount(), manager.Ready(), manager.Snapshot().ActiveKID())
	}
	if logs.String() != "attestation keyring reload rejected\n" {
		t.Fatalf("reload log = %q", logs.String())
	}

	replaceKeyring(t, path, makeKeyringJSON("rotation-2026-09", makeTestKey("rotation-2026-09", StateActive, 4), activeRetired(active)))
	if err := manager.Reload(); err != nil {
		t.Fatalf("valid Reload() error = %v", err)
	}
	if manager.Snapshot().ActiveKID() != "rotation-2026-09" {
		t.Fatalf("active after reload = %q", manager.Snapshot().ActiveKID())
	}
	if manager.ReloadSuccessCount() != 1 || manager.ReloadFailureCount() != 1 {
		t.Fatalf("reload counters = success=%d failure=%d", manager.ReloadSuccessCount(), manager.ReloadFailureCount())
	}
	newSigned, err := manager.Sign(testClaims(testIssuer))
	if err != nil {
		t.Fatalf("replacement Sign() error = %v", err)
	}
	if _, err := attestation.Verify(newSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager}); err != nil {
		t.Fatalf("replacement verification error = %v", err)
	}
	if _, err := attestation.Verify(oldSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager}); err != nil {
		t.Fatalf("historical verification after reload error = %v", err)
	}
}

func activeRetired(key testKey) testKey {
	key.state = StateRetired
	key.privateSeed = nil
	return key
}

type logBuffer struct{ buffer *bytes.Buffer }

func (l logBuffer) Printf(format string, args ...any) { fmt.Fprintf(l.buffer, format+"\n", args...) }

func TestManagerRevocationAndPolling(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	path := writeKeyring(t, makeKeyringJSON(active.id, active))
	manager, err := NewManager(path, testIssuer)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()
	oldSigned, err := manager.Sign(testClaims(testIssuer))
	if err != nil {
		t.Fatalf("initial Sign() error = %v", err)
	}

	replacement := makeTestKey("rotation-2026-09", StateActive, 4)
	retired := active
	retired.state = StateRetired
	retired.privateSeed = nil
	replaceKeyring(t, path, makeKeyringJSON(replacement.id, retired, replacement))
	ctx, cancel := context.WithCancel(context.Background())
	if err := manager.start(ctx, 5*time.Millisecond); err != nil {
		t.Fatalf("start() error = %v", err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for manager.Snapshot().ActiveKID() != replacement.id && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if manager.Snapshot().ActiveKID() != replacement.id {
		t.Fatalf("polling did not load replacement; active=%q", manager.Snapshot().ActiveKID())
	}
	newSigned, err := manager.Sign(testClaims(testIssuer))
	if err != nil {
		t.Fatalf("replacement Sign() error = %v", err)
	}
	if _, err := attestation.Verify(newSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager}); err != nil {
		t.Fatalf("replacement verification error = %v", err)
	}
	if _, err := attestation.Verify(oldSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager}); err != nil {
		t.Fatalf("retired historical verification error = %v", err)
	}

	revoked := retired
	revoked.state = StateRevoked
	replaceKeyring(t, path, makeKeyringJSON(replacement.id, revoked, replacement))
	if err := manager.Reload(); err != nil {
		t.Fatalf("revocation Reload() error = %v", err)
	}
	_, err = attestation.Verify(oldSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager})
	var verificationErr *attestation.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Reason() != attestation.KeyRevoked {
		t.Fatalf("revoked verification error = %v, want key_revoked", err)
	}
	if _, err := attestation.Verify(newSigned, attestation.VerifyOptions{ExpectedIssuer: testIssuer, Resolver: manager}); err != nil {
		t.Fatalf("active replacement verification after revocation error = %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if manager.Ready() {
		t.Fatal("closed manager reports ready")
	}
}

func TestManagerConcurrentOperationsDuringReload(t *testing.T) {
	active := makeTestKey("rotation-2026-08", StateActive, 1)
	path := writeKeyring(t, makeKeyringJSON(active.id, active))
	manager, err := NewManager(path, testIssuer)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()
	claims := testClaims(testIssuer)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				if _, err := manager.Sign(claims); err != nil {
					t.Errorf("Sign() error = %v", err)
					return
				}
				if _, err := manager.Resolve(testIssuer, active.id); err != nil {
					t.Errorf("Resolve() error = %v", err)
					return
				}
				if _, err := manager.MetadataJSON(); err != nil {
					t.Errorf("MetadataJSON() error = %v", err)
					return
				}
			}
		}()
	}
	replacement := makeTestKey("rotation-2026-09", StateActive, 4)
	retired := active
	retired.state = StateRetired
	retired.privateSeed = nil
	replaceKeyring(t, path, makeKeyringJSON(replacement.id, retired, replacement))
	close(start)
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- manager.Reload() }()
	if err := <-reloadDone; err != nil {
		t.Fatalf("replacement Reload() error = %v", err)
	}
	wg.Wait()
}

func TestNewManagerRejectsMissingOrInvalidInitialFile(t *testing.T) {
	if _, err := NewManager(filepath.Join(t.TempDir(), "missing.json"), testIssuer); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("missing manager error = %v", err)
	}
	path := writeKeyring(t, []byte(`{"version":1,"active":"rotation-2026-08","keys":[]}`))
	if _, err := NewManager(path, testIssuer); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("invalid manager error = %v", err)
	}
	if _, err := NewManager(path, "http://vaultsmith.example.test"); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("invalid issuer manager error = %v", err)
	}
}
