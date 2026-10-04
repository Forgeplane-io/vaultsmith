package attestation

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
)

var (
	inputDigestDomain  = []byte("vaultsmith:rotation-attestation:input:v1\x00")
	outputDigestDomain = []byte("vaultsmith:rotation-attestation:output:v1\x00")
)

// InputDigest canonicalizes a Vault envelope and returns its lowercase
// domain-separated SHA-256 digest.
func InputDigest(value string) (string, error) {
	canonical, err := ansiblevault.CanonicalEnvelope(value)
	if err != nil {
		return "", errMalformed
	}
	return digestCanonical(inputDigestDomain, canonical), nil
}

// OutputDigest canonicalizes a Vault envelope and returns its lowercase
// domain-separated SHA-256 digest. It uses a distinct role prefix from
// InputDigest, so swapping the two claims cannot verify.
func OutputDigest(value string) (string, error) {
	canonical, err := ansiblevault.CanonicalEnvelope(value)
	if err != nil {
		return "", errMalformed
	}
	return digestCanonical(outputDigestDomain, canonical), nil
}

// InputDigestBytes hashes canonical envelope bytes directly. It is useful to
// callers that have already called ansiblevault.CanonicalEnvelope.
func InputDigestBytes(canonical []byte) string {
	return digestCanonical(inputDigestDomain, canonical)
}

// OutputDigestBytes hashes canonical envelope bytes directly using the output
// role domain.
func OutputDigestBytes(canonical []byte) string {
	return digestCanonical(outputDigestDomain, canonical)
}

func digestCanonical(domain, canonical []byte) string {
	input := make([]byte, 0, len(domain)+len(canonical))
	input = append(input, domain...)
	input = append(input, canonical...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}
