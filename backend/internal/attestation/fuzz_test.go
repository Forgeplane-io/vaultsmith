package attestation

import (
	"testing"
)

func FuzzParseJWS(f *testing.F) {
	claims := testClaimsForFuzz()
	if signed, err := Sign(claims, testKid, testPrivateKey()); err == nil {
		if data, err := Marshal(signed); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		parsed, err := Parse(data)
		if err != nil {
			return
		}
		_, _ = Verify(parsed, VerifyOptions{
			ExpectedIssuer: testIssuer,
			Resolver:       resolverFor(testPrivateKey(), false),
		})
	})
}

func FuzzStrictClaims(f *testing.F) {
	claims := testClaimsForFuzz()
	if canonical, err := canonicalClaims(claims); err == nil {
		f.Add(canonical)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = parseCanonicalClaims(data)
	})
}

func FuzzCanonicalEnvelope(f *testing.F) {
	f.Add(testEnvelope("fuzz"))
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > (5<<20)+256 {
			t.Skip()
		}
		_, _ = canonicalEnvelopeArgument(value)
	})
}

func testClaimsForFuzz() RotationClaims {
	input, _ := InputDigest(testEnvelope("input"))
	output, _ := OutputDigest(testEnvelope("output"))
	return RotationClaims{
		Version:              1,
		Issuer:               testIssuer,
		IssuedAt:             "2026-08-15T12:34:56.123Z",
		Operation:            "rotate",
		SourceProfileID:      "source",
		DestinationProfileID: "destination",
		Input:                Digest{Algorithm: "sha-256", Value: input},
		Output:               Digest{Algorithm: "sha-256", Value: output},
	}
}
