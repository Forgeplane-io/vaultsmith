package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/gowebpki/jcs"
)

// KeyResolution is the issuer-bound result of a key lookup.
type KeyResolution struct {
	PublicKey ed25519.PublicKey
	Revoked   bool
}

// KeyResolver resolves a verification key by both signed issuer and kid. An
// implementation must not resolve by kid alone.
type KeyResolver interface {
	Resolve(issuer, kid string) (KeyResolution, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(issuer, kid string) (KeyResolution, error)

// Resolve implements KeyResolver.
func (f KeyResolverFunc) Resolve(issuer, kid string) (KeyResolution, error) {
	if f == nil {
		return KeyResolution{}, errors.New("key not found")
	}
	return f(issuer, kid)
}

// VerifyOptions contains the required issuer and issuer-bound resolver. The
// optional digest, envelope, and binding fields let a caller perform the
// complete semantic check without putting those values into the JWS parser.
type VerifyOptions struct {
	ExpectedIssuer string
	Resolver       KeyResolver

	// ExpectedInputDigest and ExpectedOutputDigest compare against already
	// canonicalized digest values. They must be lowercase SHA-256 hex.
	ExpectedInputDigest  string
	ExpectedOutputDigest string

	// InputVaultText and OutputVaultText are optional raw Vault envelopes. When
	// set, Verify canonicalizes them only after signature and version checks.
	InputVaultText  string
	OutputVaultText string

	// ExpectedBinding is an optional partial exact-match expectation.
	ExpectedBinding *Binding
}

type protectedHeader struct {
	Alg string
	Kid string
	Typ string
}

var protectedMembers = map[string]struct{}{
	"alg": {}, "kid": {}, "typ": {},
}

// Sign validates v1 typed claims and emits a flattened Ed25519 JWS. Future
// versions remain verifiable through test-only/raw construction so Verify can
// report unsupported_version, but the public v1 signer cannot mint them.
func Sign(claims RotationClaims, kid string, privateKey ed25519.PrivateKey) (Signed, error) {
	if err := validateSigningClaims(claims); err != nil {
		return Signed{}, ErrMalformed
	}
	if !validKID(kid) {
		return Signed{}, ErrMalformed
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalidSigningKey
	}

	protectedBytes, err := canonicalProtectedHeader(protectedHeader{
		Alg: attestationAlgorithm,
		Kid: kid,
		Typ: attestationType,
	})
	if err != nil {
		return Signed{}, ErrMalformed
	}
	payloadBytes, err := canonicalClaims(claims)
	if err != nil {
		return Signed{}, ErrMalformed
	}
	protected := encodeBase64URL(protectedBytes)
	payload := encodeBase64URL(payloadBytes)
	signingInput := []byte(protected + "." + payload)
	signature := ed25519.Sign(privateKey, signingInput)
	return Signed{
		Protected: protected,
		Payload:   payload,
		Signature: encodeBase64URL(signature),
	}, nil
}

// SignAndMarshal signs claims and returns deterministic flattened JWS JSON.
func SignAndMarshal(claims RotationClaims, kid string, privateKey ed25519.PrivateKey) ([]byte, error) {
	signed, err := Sign(claims, kid, privateKey)
	if err != nil {
		return nil, err
	}
	return Marshal(signed)
}

// Verify checks a flattened JWS using the fixed protocol precedence. It
// returns claims only after a valid signature; semantic failures after that
// point return the parsed claims alongside a safe VerificationError.
func Verify(signed Signed, options VerifyOptions) (RotationClaims, error) {
	if err := validateVerifyOptions(options); err != nil {
		return RotationClaims{}, err
	}

	protectedBytes, payloadBytes, signature, err := decodeEncodedComponents(signed)
	if err != nil {
		return RotationClaims{}, ErrMalformed
	}
	header, err := parseCanonicalProtected(protectedBytes)
	if err != nil {
		return RotationClaims{}, ErrMalformed
	}
	claims, err := parseCanonicalClaims(payloadBytes)
	if err != nil {
		return RotationClaims{}, ErrMalformed
	}

	if claims.Issuer != options.ExpectedIssuer {
		return RotationClaims{}, newVerificationError(IssuerMismatch)
	}

	resolution, resolveErr := options.Resolver.Resolve(claims.Issuer, header.Kid)
	if resolveErr != nil || len(resolution.PublicKey) != ed25519.PublicKeySize {
		return RotationClaims{}, newVerificationError(UnknownKey)
	}

	signingInput := []byte(signed.Protected + "." + signed.Payload)
	if !ed25519.Verify(resolution.PublicKey, signingInput, signature) {
		return RotationClaims{}, newVerificationError(SignatureInvalid)
	}
	if resolution.Revoked {
		return claims, newVerificationError(KeyRevoked)
	}
	if claims.Version != SupportedVersion {
		return claims, newVerificationError(UnsupportedVersion)
	}

	if options.InputVaultText != "" {
		digest, digestErr := InputDigest(options.InputVaultText)
		if digestErr != nil {
			return RotationClaims{}, ErrMalformed
		}
		if subtle.ConstantTimeCompare([]byte(claims.Input.Value), []byte(digest)) != 1 {
			return claims, newVerificationError(InputDigestMismatch)
		}
	} else if options.ExpectedInputDigest != "" && subtle.ConstantTimeCompare(
		[]byte(claims.Input.Value), []byte(options.ExpectedInputDigest)) != 1 {
		return claims, newVerificationError(InputDigestMismatch)
	}

	if options.OutputVaultText != "" {
		digest, digestErr := OutputDigest(options.OutputVaultText)
		if digestErr != nil {
			return RotationClaims{}, ErrMalformed
		}
		if subtle.ConstantTimeCompare([]byte(claims.Output.Value), []byte(digest)) != 1 {
			return claims, newVerificationError(OutputDigestMismatch)
		}
	} else if options.ExpectedOutputDigest != "" && subtle.ConstantTimeCompare(
		[]byte(claims.Output.Value), []byte(options.ExpectedOutputDigest)) != 1 {
		return claims, newVerificationError(OutputDigestMismatch)
	}

	if options.ExpectedBinding != nil && !bindingMatches(claims.Binding, *options.ExpectedBinding) {
		return claims, newVerificationError(BindingMismatch)
	}
	return claims, nil
}

// VerifyJSON parses and verifies a flattened JWS JSON object.
func VerifyJSON(data []byte, options VerifyOptions) (RotationClaims, error) {
	signed, err := Parse(data)
	if err != nil {
		return RotationClaims{}, ErrMalformed
	}
	return Verify(signed, options)
}

// VerifyAgainstEnvelopes performs verification and computes the two
// role-specific digests from the supplied Vault envelopes only after the
// cryptographic and version checks required by the protocol precedence.
func VerifyAgainstEnvelopes(signed Signed, input, output string, expectedBinding *Binding, options VerifyOptions) (RotationClaims, error) {
	options.InputVaultText = input
	options.OutputVaultText = output
	options.ExpectedBinding = expectedBinding
	return Verify(signed, options)
}

// SigningInput returns the RFC 7515 signing input after checking that all three
// encoded JWS components are canonical and length-valid.
func SigningInput(signed Signed) ([]byte, error) {
	_, _, signature, err := decodeEncodedComponents(signed)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	return []byte(signed.Protected + "." + signed.Payload), nil
}

func validateVerifyOptions(options VerifyOptions) error {
	if options.Resolver == nil || !validIssuer(options.ExpectedIssuer) {
		return ErrInvalidVerifyOptions
	}
	if options.ExpectedInputDigest != "" && !validLowerHexDigest(options.ExpectedInputDigest) {
		return ErrInvalidVerifyOptions
	}
	if options.ExpectedOutputDigest != "" && !validLowerHexDigest(options.ExpectedOutputDigest) {
		return ErrInvalidVerifyOptions
	}
	if options.ExpectedBinding != nil {
		if err := validateBinding(*options.ExpectedBinding); err != nil {
			return ErrInvalidVerifyOptions
		}
	}
	return nil
}

func parseCanonicalProtected(data []byte) (protectedHeader, error) {
	root, err := parseStrictJSON(data)
	if err != nil || root.kind != jsonObject || !root.hasOnlyMembers(protectedMembers) {
		return protectedHeader{}, errMalformed
	}
	alg, err := requiredStringMember(root, "alg")
	if err != nil {
		return protectedHeader{}, errMalformed
	}
	kid, err := requiredStringMember(root, "kid")
	if err != nil || !validKID(kid) {
		return protectedHeader{}, errMalformed
	}
	typ, err := requiredStringMember(root, "typ")
	if err != nil || typ == "" || !stringsEqualFoldASCII(typ, attestationType) {
		return protectedHeader{}, errMalformed
	}
	if alg != attestationAlgorithm {
		return protectedHeader{}, errMalformed
	}
	canonical, err := jcs.Transform(data)
	if err != nil || !bytes.Equal(canonical, data) {
		return protectedHeader{}, errMalformed
	}
	return protectedHeader{Alg: alg, Kid: kid, Typ: typ}, nil
}

func canonicalProtectedHeader(header protectedHeader) ([]byte, error) {
	raw, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{Alg: header.Alg, Kid: header.Kid, Typ: header.Typ})
	if err != nil {
		return nil, errMalformed
	}
	return jcs.Transform(raw)
}

func bindingMatches(actual *Binding, expected Binding) bool {
	if actual == nil {
		return false
	}
	if expected.Repository != "" && actual.Repository != expected.Repository {
		return false
	}
	if expected.Revision != "" && actual.Revision != expected.Revision {
		return false
	}
	if expected.Path != "" && actual.Path != expected.Path {
		return false
	}
	if expected.Selector != "" && actual.Selector != expected.Selector {
		return false
	}
	return true
}

func stringsEqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		left, right := a[index], b[index]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}
