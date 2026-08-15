package attestationkeyring

import (
	"encoding/base64"
	"encoding/json"

	"github.com/gowebpki/jcs"
)

// Metadata is the non-secret attestation discovery document.
type Metadata struct {
	Issuer              string   `json:"issuer"`
	ActiveKID           string   `json:"activeKid"`
	AttestationVersions []int64  `json:"attestationVersions"`
	JWKSURI             string   `json:"jwksUri"`
	RevokedKids         []string `json:"revokedKids"`
}

// JWK is a public Ed25519 verification key in the local discovery document.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// JWKS is the deterministic public-key discovery document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Metadata returns a detached non-secret discovery model.
func (s *Snapshot) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	revoked := make([]string, 0)
	for _, id := range s.orderedIDs {
		if s.keys[id].state == StateRevoked {
			revoked = append(revoked, id)
		}
	}
	return Metadata{
		Issuer:              s.issuer,
		ActiveKID:           s.active,
		AttestationVersions: []int64{1},
		JWKSURI:             s.issuer + "/.well-known/vaultsmith-attestation/jwks.json",
		RevokedKids:         revoked,
	}
}

// JWKS returns a detached public-only discovery model. Revoked keys are
// intentionally omitted while remaining available to the local resolver.
func (s *Snapshot) JWKS() JWKS {
	if s == nil {
		return JWKS{}
	}
	keys := make([]JWK, 0, len(s.orderedIDs))
	for _, id := range s.orderedIDs {
		entry := s.keys[id]
		if entry.state == StateRevoked {
			continue
		}
		keys = append(keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Alg: "Ed25519",
			Use: "sig",
			Kid: entry.id,
			X:   base64.RawURLEncoding.EncodeToString(entry.publicKey[:]),
		})
	}
	return JWKS{Keys: keys}
}

// MetadataJSON returns deterministic JCS bytes for the metadata document.
func (s *Snapshot) MetadataJSON() ([]byte, error) {
	if s == nil {
		return nil, ErrNotReady
	}
	return canonicalJSON(s.Metadata())
}

// JWKSJSON returns deterministic JCS bytes for the public JWKS document.
func (s *Snapshot) JWKSJSON() ([]byte, error) {
	if s == nil {
		return nil, ErrNotReady
	}
	return canonicalJSON(s.JWKS())
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	return canonical, nil
}
