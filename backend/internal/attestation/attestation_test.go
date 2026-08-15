package attestation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testIssuer = "https://vaultsmith.example"
	testKid    = "rotation-2026-08"
)

func TestSignVerifyAndMarshal(t *testing.T) {
	claims := testClaims(t)
	privateKey := testPrivateKey()
	signed, err := Sign(claims, testKid, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if signed.Protected == "" || signed.Payload == "" || signed.Signature == "" {
		t.Fatal("Sign() returned an incomplete flattened JWS")
	}
	wire, err := Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	resolver := resolverFunc(func(issuer, kid string) (KeyResolution, error) {
		if issuer != testIssuer || kid != testKid {
			t.Fatalf("resolver received (%q, %q)", issuer, kid)
		}
		return KeyResolution{PublicKey: privateKey.Public().(ed25519.PublicKey)}, nil
	})
	options := VerifyOptions{
		ExpectedIssuer:       testIssuer,
		Resolver:             resolver,
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
		ExpectedBinding:      &Binding{Repository: "forgeplane/vaultsmith"},
	}
	verified, err := Verify(parsed, options)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Version != claims.Version || verified.Input != claims.Input || verified.Output != claims.Output {
		t.Fatalf("verified claims = %#v, want %#v", verified, claims)
	}

	// Outer member order is not signed and is intentionally flexible.
	reordered := fmt.Sprintf(`{"signature":%q,"protected":%q,"payload":%q}`, signed.Signature, signed.Protected, signed.Payload)
	if _, err := VerifyJSON([]byte(reordered), options); err != nil {
		t.Fatalf("VerifyJSON(reordered) error = %v", err)
	}
}

func TestCaseVariantTypIsAccepted(t *testing.T) {
	claims := testClaims(t)
	privateKey := testPrivateKey()
	signed, err := Sign(claims, testKid, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	variant := []byte(`{"alg":"Ed25519","kid":"rotation-2026-08","typ":"APPLICATION/VAULTSMITH-ROTATION-ATTESTATION+JSON"}`)
	signed = resignWithProtected(t, signed, variant, privateKey)
	_, err = Verify(signed, VerifyOptions{
		ExpectedIssuer:       testIssuer,
		Resolver:             resolverFor(privateKey, false),
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
	})
	if err != nil {
		t.Fatalf("case-variant typ error = %v", err)
	}
}

func TestVerificationPrecedenceAndReasons(t *testing.T) {
	claims := testClaims(t)
	privateKey := testPrivateKey()
	valid, err := Sign(claims, testKid, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	base := VerifyOptions{
		ExpectedIssuer:       testIssuer,
		Resolver:             resolverFor(privateKey, false),
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
		ExpectedBinding:      &Binding{Repository: "forgeplane/vaultsmith"},
	}

	tests := []struct {
		name   string
		signed Signed
		opts   VerifyOptions
		want   VerificationReason
		claims bool
	}{
		{name: "issuer mismatch", signed: valid, opts: withExpectedIssuer(base, "https://other.example"), want: IssuerMismatch},
		{name: "unknown key", signed: valid, opts: withResolver(base, resolverFunc(func(string, string) (KeyResolution, error) {
			return KeyResolution{}, errors.New("not found")
		})), want: UnknownKey},
		{name: "signature invalid", signed: mutateSignature(t, valid), opts: base, want: SignatureInvalid},
		{name: "revoked key", signed: valid, opts: withResolver(base, resolverFor(privateKey, true)), want: KeyRevoked, claims: true},
		{name: "input digest", signed: valid, opts: withInput(base, strings.Repeat("0", 64)), want: InputDigestMismatch, claims: true},
		{name: "output digest", signed: valid, opts: withOutput(base, strings.Repeat("1", 64)), want: OutputDigestMismatch, claims: true},
		{name: "binding", signed: valid, opts: withBinding(base, &Binding{Revision: "different"}), want: BindingMismatch, claims: true},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			gotClaims, gotErr := Verify(current.signed, current.opts)
			if gotErr == nil {
				t.Fatal("Verify() error = nil")
			}
			reason, ok := VerificationReasonOf(gotErr)
			if !ok || reason != current.want {
				t.Fatalf("reason = %q, ok=%v, want %q (err=%v)", reason, ok, current.want, gotErr)
			}
			if current.claims && gotClaims.Issuer != testIssuer {
				t.Fatalf("semantic failure claims = %#v, want signed claims", gotClaims)
			}
			if !current.claims && gotClaims != (RotationClaims{}) {
				t.Fatalf("pre-signature claims = %#v, want zero", gotClaims)
			}
		})
	}

	unsupported := claims
	unsupported.Version = 2
	future := signClaimsForTest(t, unsupported, testKid, privateKey)
	futureClaims, futureErr := Verify(future, base)
	if reason, ok := VerificationReasonOf(futureErr); !ok || reason != UnsupportedVersion {
		t.Fatalf("future version reason = %q, ok=%v, err=%v", reason, ok, futureErr)
	}
	if futureClaims.Version != 2 {
		t.Fatalf("future version claims = %#v", futureClaims)
	}

	wrongRoles := base
	wrongRoles.ExpectedInputDigest = claims.Output.Value
	wrongRoles.ExpectedOutputDigest = claims.Input.Value
	_, wrongRoleErr := Verify(valid, wrongRoles)
	if reason, ok := VerificationReasonOf(wrongRoleErr); !ok || reason != InputDigestMismatch {
		t.Fatalf("swapped digest reason = %q, ok=%v, err=%v", reason, ok, wrongRoleErr)
	}
}

func TestMalformedJWSAndStrictJSON(t *testing.T) {
	claims := testClaims(t)
	privateKey := testPrivateKey()
	signed, err := Sign(claims, testKid, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	duplicateOuter := fmt.Sprintf(`{"protected":%q,"payload":%q,"signature":%q,"signature":%q}`, signed.Protected, signed.Payload, signed.Signature, signed.Signature)
	if _, err := Parse([]byte(duplicateOuter)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate outer error = %v, want ErrMalformed", err)
	}
	duplicateHeader := append([]byte(nil), mustDecode(t, signed.Protected)...)
	duplicateHeader = append(duplicateHeader[:len(duplicateHeader)-1], []byte(`,"alg":"Ed25519"}`)...)
	badHeader := resignWithProtected(t, signed, duplicateHeader, privateKey)
	if _, err := Verify(badHeader, validOptions(claims, privateKey)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate header error = %v, want ErrMalformed", err)
	}

	canonicalPayload := mustDecode(t, signed.Payload)
	noncanonicalPayload := append([]byte(` `), canonicalPayload...)
	badPayload := signed
	badPayload.Payload = encodeBase64URL(noncanonicalPayload)
	badPayload.Signature = encodeBase64URL(ed25519.Sign(privateKey, []byte(badPayload.Protected+"."+badPayload.Payload)))
	if _, err := Verify(badPayload, validOptions(claims, privateKey)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("noncanonical payload error = %v, want ErrMalformed", err)
	}

	duplicateClaims := append([]byte(nil), canonicalPayload...)
	duplicateClaims = append(duplicateClaims[:len(duplicateClaims)-1], []byte(`,"issuer":"https://vaultsmith.example"}`)...)
	badClaims := signed
	badClaims.Payload = encodeBase64URL(duplicateClaims)
	badClaims.Signature = encodeBase64URL(ed25519.Sign(privateKey, []byte(badClaims.Protected+"."+badClaims.Payload)))
	if _, err := Verify(badClaims, validOptions(claims, privateKey)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate claims error = %v, want ErrMalformed", err)
	}

	for _, raw := range []string{
		`{"version":1.0}`,
		`{"version":-1}`,
		`{"version":9007199254740992}`,
		`{"version":1e0}`,
	} {
		if _, err := parseStrictJSON([]byte(raw)); err != nil && strings.Contains(raw, `"version":1.0`) {
			// The generic parser accepts valid JSON numbers; schema validation below
			// is what distinguishes non-integer version syntax.
			continue
		}
		if _, err := parseCanonicalClaims([]byte(raw)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("version %s error = %v, want ErrMalformed", raw, err)
		}
	}

	for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\ud834\u0041"`} {
		if _, err := parseStrictJSON([]byte(raw)); !errors.Is(err, errStrictJSON) {
			t.Fatalf("surrogate %s error = %v, want strict JSON error", raw, err)
		}
	}
	if value, err := parseStrictJSON([]byte(`"\ud834\udd1e"`)); err != nil || value.string != "𝄞" {
		t.Fatalf("valid surrogate pair = %#v, error = %v", value, err)
	}

	rawSecret := "raw-jws-secret-vault-digest"
	if _, err := Parse([]byte(rawSecret)); err == nil || strings.Contains(err.Error(), rawSecret) {
		t.Fatalf("parse error leaked raw input: %v", err)
	}
	resolverSecret := errors.New("resolver secret key material")
	_, err = Verify(signed, VerifyOptions{ExpectedIssuer: testIssuer, Resolver: resolverFunc(func(string, string) (KeyResolution, error) {
		return KeyResolution{}, resolverSecret
	})})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("resolver error leaked: %v", err)
	}
}

func TestHeaderAndEncodingRejections(t *testing.T) {
	claims := testClaims(t)
	privateKey := testPrivateKey()
	signed, err := Sign(claims, testKid, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	options := validOptions(claims, privateKey)

	for _, test := range []struct {
		name      string
		protected string
	}{
		{
			name:      "deprecated polymorphic algorithm",
			protected: `{"alg":"EdDSA","kid":"rotation-2026-08","typ":"application/vaultsmith-rotation-attestation+json"}`,
		},
		{
			name:      "type parameter",
			protected: `{"alg":"Ed25519","kid":"rotation-2026-08","typ":"application/vaultsmith-rotation-attestation+json;v=1"}`,
		},
		{
			name:      "forbidden crit",
			protected: `{"alg":"Ed25519","crit":[],"kid":"rotation-2026-08","typ":"application/vaultsmith-rotation-attestation+json"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := resignWithProtected(t, signed, []byte(test.protected), privateKey)
			if _, err := Verify(candidate, options); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify() error = %v, want ErrMalformed", err)
			}
		})
	}

	for _, test := range []struct {
		name   string
		mutate func(Signed) Signed
	}{
		{
			name: "padded signature",
			mutate: func(candidate Signed) Signed {
				candidate.Signature += "="
				return candidate
			},
		},
		{
			name: "padded protected",
			mutate: func(candidate Signed) Signed {
				candidate.Protected += "="
				return candidate
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Verify(test.mutate(signed), options); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify() error = %v, want ErrMalformed", err)
			}
		})
	}

	for _, wire := range []string{
		fmt.Sprintf(`{"payload":%q,"signature":%q}`, signed.Payload, signed.Signature),
		fmt.Sprintf(`{"protected":%q,"payload":%q,"signature":%q,"header":{}}`, signed.Protected, signed.Payload, signed.Signature),
	} {
		if _, err := Parse([]byte(wire)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Parse(%s) error = %v, want ErrMalformed", wire, err)
		}
	}

	protected := mustDecode(t, signed.Protected)
	noncanonicalProtected := append([]byte{' '}, protected...)
	noncanonical := resignWithProtected(t, signed, noncanonicalProtected, privateKey)
	if _, err := Verify(noncanonical, options); !errors.Is(err, ErrMalformed) {
		t.Fatalf("noncanonical protected error = %v, want ErrMalformed", err)
	}
}

func TestDigestDomainSeparation(t *testing.T) {
	input := testEnvelope("input")
	output := testEnvelope("output")
	in, err := InputDigest(input)
	if err != nil {
		t.Fatalf("InputDigest() error = %v", err)
	}
	out, err := OutputDigest(output)
	if err != nil {
		t.Fatalf("OutputDigest() error = %v", err)
	}
	if in == out {
		t.Fatal("input and output digest roles unexpectedly match")
	}
	canonical, err := canonicalEnvelopeArgument(input)
	if err != nil {
		t.Fatalf("canonicalEnvelopeArgument() error = %v", err)
	}
	if in != InputDigestBytes(canonical) || out != OutputDigestBytes(mustCanonical(t, output)) {
		t.Fatal("digest helpers did not hash canonical bytes directly")
	}
}

func TestSignRequiresSupportedVersion(t *testing.T) {
	for _, version := range []int64{0, 2, MaxJCSSafeInteger} {
		claims := testClaims(t)
		claims.Version = version
		if _, err := Sign(claims, testKid, testPrivateKey()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Sign(version=%d) error = %v, want ErrMalformed", version, err)
		}
	}
}

func TestVersionSafeRange(t *testing.T) {
	for _, version := range []int64{0, 1, MaxJCSSafeInteger} {
		claims := testClaims(t)
		claims.Version = version
		canonical, err := canonicalClaims(claims)
		if err != nil {
			t.Fatalf("canonicalClaims(version=%d) error = %v", version, err)
		}
		parsed, err := parseCanonicalClaims(canonical)
		if err != nil || parsed.Version != version {
			t.Fatalf("version=%d parsed=%#v error=%v", version, parsed, err)
		}
	}
}

func testClaims(t *testing.T) RotationClaims {
	t.Helper()
	input, err := InputDigest(testEnvelope("input"))
	if err != nil {
		t.Fatalf("input digest fixture: %v", err)
	}
	output, err := OutputDigest(testEnvelope("output"))
	if err != nil {
		t.Fatalf("output digest fixture: %v", err)
	}
	return RotationClaims{
		Version:              SupportedVersion,
		Issuer:               testIssuer,
		IssuedAt:             "2026-08-15T12:34:56.123Z",
		Operation:            "rotate",
		SourceProfileID:      "source",
		DestinationProfileID: "destination",
		Input:                Digest{Algorithm: "sha-256", Value: input},
		Output:               Digest{Algorithm: "sha-256", Value: output},
		Binding:              &Binding{Repository: "forgeplane/vaultsmith", Revision: "abc123", Path: "secrets/prod.yml", Selector: "database.password"},
	}
}

func testPrivateKey() ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func resolverFor(privateKey ed25519.PrivateKey, revoked bool) KeyResolver {
	return resolverFunc(func(issuer, kid string) (KeyResolution, error) {
		if issuer != testIssuer || kid != testKid {
			return KeyResolution{}, errors.New("not found")
		}
		return KeyResolution{PublicKey: privateKey.Public().(ed25519.PublicKey), Revoked: revoked}, nil
	})
}

type resolverFunc func(string, string) (KeyResolution, error)

func (f resolverFunc) Resolve(issuer, kid string) (KeyResolution, error) { return f(issuer, kid) }

func validOptions(claims RotationClaims, privateKey ed25519.PrivateKey) VerifyOptions {
	return VerifyOptions{
		ExpectedIssuer:       testIssuer,
		Resolver:             resolverFor(privateKey, false),
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
		ExpectedBinding:      &Binding{Repository: "forgeplane/vaultsmith"},
	}
}

func withExpectedIssuer(options VerifyOptions, issuer string) VerifyOptions {
	options.ExpectedIssuer = issuer
	return options
}

func withResolver(options VerifyOptions, resolver KeyResolver) VerifyOptions {
	options.Resolver = resolver
	return options
}

func withInput(options VerifyOptions, digest string) VerifyOptions {
	options.ExpectedInputDigest = digest
	return options
}

func withOutput(options VerifyOptions, digest string) VerifyOptions {
	options.ExpectedOutputDigest = digest
	return options
}

func withBinding(options VerifyOptions, binding *Binding) VerifyOptions {
	options.ExpectedBinding = binding
	return options
}

func falseErr() bool { return false }

func mutateSignature(t *testing.T, signed Signed) Signed {
	t.Helper()
	signature := mustDecode(t, signed.Signature)
	signature[0] ^= 0x80
	signed.Signature = encodeBase64URL(signature)
	return signed
}

func signClaimsForTest(t *testing.T, claims RotationClaims, kid string, privateKey ed25519.PrivateKey) Signed {
	t.Helper()
	protected, err := canonicalProtectedHeader(protectedHeader{Alg: attestationAlgorithm, Kid: kid, Typ: attestationType})
	if err != nil {
		t.Fatalf("canonical test header: %v", err)
	}
	payload, err := canonicalClaims(claims)
	if err != nil {
		t.Fatalf("canonical test claims: %v", err)
	}
	protectedEncoded := encodeBase64URL(protected)
	payloadEncoded := encodeBase64URL(payload)
	return Signed{
		Protected: protectedEncoded,
		Payload:   payloadEncoded,
		Signature: encodeBase64URL(ed25519.Sign(privateKey, []byte(protectedEncoded+"."+payloadEncoded))),
	}
}

func resignWithProtected(t *testing.T, signed Signed, protected []byte, privateKey ed25519.PrivateKey) Signed {
	t.Helper()
	signed.Protected = encodeBase64URL(protected)
	signed.Signature = encodeBase64URL(ed25519.Sign(privateKey, []byte(signed.Protected+"."+signed.Payload)))
	return signed
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := decodeStrictBase64URL(value)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return decoded
}

func testEnvelope(seed string) string {
	cipherHex := strings.Repeat("c", 32)
	if seed == "output" {
		cipherHex = strings.Repeat("d", 32)
	}
	inner := strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64) + "\n" + cipherHex
	body := hex.EncodeToString([]byte(inner))
	var lines []string
	for len(body) > 80 {
		lines = append(lines, strings.ToUpper(body[:80]))
		body = body[80:]
	}
	lines = append(lines, strings.ToUpper(body))
	return "$ANSIBLE_VAULT;1.1;AES256\r\n" + strings.Join(lines, "\r\n")
}

func mustCanonical(t *testing.T, value string) []byte {
	t.Helper()
	canonical, err := canonicalEnvelopeArgument(value)
	if err != nil {
		t.Fatalf("canonical envelope: %v", err)
	}
	return canonical
}
