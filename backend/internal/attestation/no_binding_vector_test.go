package attestation

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPermanentNoBindingVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vector-no-binding.json"))
	if err != nil {
		t.Fatalf("read no-binding vector: %v", err)
	}
	var vector goldenVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode no-binding vector: %v", err)
	}
	parsed, err := Parse(mustMarshal(t, vector.JWS))
	if err != nil {
		t.Fatalf("parse no-binding vector: %v", err)
	}
	protected, payload, signature, err := decodeEncodedComponents(parsed)
	if err != nil {
		t.Fatalf("decode no-binding vector: %v", err)
	}
	if string(protected) != vector.CanonicalProtected || string(payload) != vector.CanonicalClaims || len(signature) != 64 {
		t.Fatal("no-binding vector bytes mismatch")
	}
	claims, err := parseCanonicalClaims(payload)
	if err != nil {
		t.Fatalf("parse no-binding claims: %v", err)
	}
	if claims.Binding != nil {
		t.Fatal("no-binding vector unexpectedly contains binding")
	}
	verified, err := Verify(parsed, VerifyOptions{
		ExpectedIssuer:       claims.Issuer,
		Resolver:             resolverForPublic(testPrivateKey().Public().(ed25519.PublicKey), false),
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
	})
	if err != nil {
		t.Fatalf("verify no-binding vector: %v", err)
	}
	if verified.Binding != nil {
		t.Fatal("verified no-binding claims unexpectedly contain binding")
	}
}
