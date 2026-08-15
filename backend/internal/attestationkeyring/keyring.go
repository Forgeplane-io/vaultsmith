package attestationkeyring

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
)

const (
	// MaxFileBytes bounds every read and parsed keyring document.
	MaxFileBytes = 64 << 10

	// MaxEntries bounds the number of retained key-history entries.
	MaxEntries = 256

	// ReloadInterval is fixed application policy, not deployment configuration.
	ReloadInterval = 5 * time.Second
)

// KeyState is the lifecycle state of one keyring entry.
type KeyState string

const (
	StateActive  KeyState = "active"
	StateRetired KeyState = "retired"
	StateRevoked KeyState = "revoked"
)

var (
	keyringMembers = map[string]struct{}{
		"version": {}, "active": {}, "keys": {},
	}
	keyMembers = map[string]struct{}{
		"id": {}, "state": {}, "publicKey": {}, "privateKey": {},
	}
	_ attestation.KeyResolver = (*Snapshot)(nil)
)

type keyEntry struct {
	id        string
	state     KeyState
	publicKey [ed25519.PublicKeySize]byte
	seed      [ed25519.SeedSize]byte
	hasSeed   bool
}

// Snapshot is a fully validated immutable keyring state. Its fields are
// private; methods return copies of public data and never expose private seeds.
type Snapshot struct {
	issuer      string
	active      string
	keys        map[string]keyEntry
	orderedIDs  []string
	contentHash [sha256.Size]byte
}

// Parse validates a complete keyring document for the configured issuer.
func Parse(data []byte, issuer string) (*Snapshot, error) {
	if len(data) > MaxFileBytes {
		return nil, ErrKeyringTooLarge
	}
	canonicalIssuer, err := canonicalIssuer(issuer)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	root, err := parseStrictJSON(data)
	if err != nil || !root.hasOnlyMembers(keyringMembers) {
		return nil, ErrInvalidKeyring
	}

	version, ok := root.member("version")
	if !ok || version.kind != jsonNumber || version.number != "1" {
		return nil, ErrInvalidKeyring
	}
	active, err := requiredString(root, "active")
	if err != nil || !validKID(active) {
		return nil, ErrInvalidKeyring
	}
	keysValue, ok := root.member("keys")
	if !ok || keysValue.kind != jsonArray || len(keysValue.array) == 0 || len(keysValue.array) > MaxEntries {
		return nil, ErrInvalidKeyring
	}

	keys := make(map[string]keyEntry, len(keysValue.array))
	orderedIDs := make([]string, 0, len(keysValue.array))
	activeCount := 0
	for _, value := range keysValue.array {
		entry, err := parseKeyEntry(value)
		if err != nil {
			return nil, ErrInvalidKeyring
		}
		if _, exists := keys[entry.id]; exists {
			return nil, ErrInvalidKeyring
		}
		keys[entry.id] = entry
		orderedIDs = append(orderedIDs, entry.id)
		if entry.state == StateActive {
			activeCount++
		}
	}
	if activeCount != 1 || keys[active].state != StateActive {
		return nil, ErrInvalidKeyring
	}
	sort.Strings(orderedIDs)
	return &Snapshot{
		issuer:      canonicalIssuer,
		active:      active,
		keys:        keys,
		orderedIDs:  orderedIDs,
		contentHash: sha256.Sum256(data),
	}, nil
}

func parseKeyEntry(value jsonValue) (keyEntry, error) {
	if value.kind != jsonObject || !value.hasOnlyMembers(keyMembers) {
		return keyEntry{}, ErrInvalidKeyring
	}
	id, err := requiredString(value, "id")
	if err != nil || !validKID(id) {
		return keyEntry{}, ErrInvalidKeyring
	}
	stateValue, err := requiredString(value, "state")
	if err != nil {
		return keyEntry{}, ErrInvalidKeyring
	}
	state := KeyState(stateValue)
	if state != StateActive && state != StateRetired && state != StateRevoked {
		return keyEntry{}, ErrInvalidKeyring
	}
	publicValue, err := requiredString(value, "publicKey")
	if err != nil {
		return keyEntry{}, ErrInvalidKeyring
	}
	publicKey, err := decodeKeyMaterial(publicValue)
	if err != nil {
		return keyEntry{}, ErrInvalidKeyring
	}
	entry := keyEntry{id: id, state: state}
	copy(entry.publicKey[:], publicKey)

	privateValue, hasPrivate := value.member("privateKey")
	if hasPrivate {
		if privateValue.kind != jsonString || privateValue.string == "" {
			return keyEntry{}, ErrInvalidKeyring
		}
		if state != StateActive {
			return keyEntry{}, ErrInvalidKeyring
		}
		seed, err := decodeKeyMaterial(privateValue.string)
		if err != nil {
			return keyEntry{}, ErrInvalidKeyring
		}
		defer clear(seed)
		privateKey := ed25519.NewKeyFromSeed(seed)
		defer clear(privateKey)
		if !bytes.Equal(privateKey[ed25519.SeedSize:], publicKey) {
			return keyEntry{}, ErrInvalidKeyring
		}
		copy(entry.seed[:], seed)
		entry.hasSeed = true
	} else if state == StateActive {
		return keyEntry{}, ErrInvalidKeyring
	}
	return entry, nil
}

func decodeKeyMaterial(value string) ([]byte, error) {
	if value == "" || strings.ContainsRune(value, '=') {
		return nil, ErrInvalidKeyring
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SeedSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidKeyring
	}
	return decoded, nil
}

func validKID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, current := range value {
		if !(current >= 'A' && current <= 'Z') &&
			!(current >= 'a' && current <= 'z') &&
			!(current >= '0' && current <= '9') && current != '.' && current != '_' && current != '-' {
			return false
		}
	}
	return true
}

func canonicalIssuer(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "?#") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", ErrInvalidKeyring
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Hostname() == "" {
		return "", ErrInvalidKeyring
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

// Issuer returns the canonical local issuer.
func (s *Snapshot) Issuer() string {
	if s == nil {
		return ""
	}
	return s.issuer
}

// ActiveKID returns the ID selected for new signatures.
func (s *Snapshot) ActiveKID() string {
	if s == nil {
		return ""
	}
	return s.active
}

// Resolve implements attestation.KeyResolver with issuer binding.
func (s *Snapshot) Resolve(issuer, kid string) (attestation.KeyResolution, error) {
	if s == nil {
		return attestation.KeyResolution{}, ErrNotReady
	}
	if issuer != s.issuer {
		return attestation.KeyResolution{}, ErrIssuerMismatch
	}
	entry, ok := s.keys[kid]
	if !ok {
		return attestation.KeyResolution{}, ErrUnknownKey
	}
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(publicKey, entry.publicKey[:])
	return attestation.KeyResolution{PublicKey: publicKey, Revoked: entry.state == StateRevoked}, nil
}

// Sign signs v1 claims with the immutable active key in this snapshot. The
// claims issuer must be the locally configured issuer.
func (s *Snapshot) Sign(claims attestation.RotationClaims) (attestation.Signed, error) {
	if s == nil {
		return attestation.Signed{}, ErrNotReady
	}
	if claims.Issuer != s.issuer {
		return attestation.Signed{}, ErrIssuerMismatch
	}
	entry, ok := s.keys[s.active]
	if !ok || !entry.hasSeed {
		return attestation.Signed{}, ErrNotReady
	}
	privateKey := ed25519.NewKeyFromSeed(entry.seed[:])
	defer clear(privateKey)
	return attestation.Sign(claims, entry.id, privateKey)
}
