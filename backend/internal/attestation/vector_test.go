package attestation

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type goldenVector struct {
	PrivateSeed        string `json:"privateSeed"`
	PublicKey          string `json:"publicKey"`
	CanonicalProtected string `json:"canonicalProtected"`
	Protected          string `json:"protected"`
	CanonicalClaims    string `json:"canonicalClaims"`
	Payload            string `json:"payload"`
	SigningInput       string `json:"signingInput"`
	SignatureHex       string `json:"signatureHex"`
	Signature          string `json:"signature"`
	JWS                Signed `json:"jws"`
}

func TestPermanentGoldenVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if strings.Contains(string(data), "...") {
		t.Fatal("golden vector contains a placeholder")
	}
	var vector goldenVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	seed, err := hex.DecodeString(vector.PrivateSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid seed fixture")
	}
	publicKey, err := hex.DecodeString(vector.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key fixture")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(privateKey.Public().(ed25519.PublicKey), publicKey) != 1 {
		t.Fatal("fixture public key does not match seed")
	}
	if vector.JWS.Protected != vector.Protected || vector.JWS.Payload != vector.Payload || vector.JWS.Signature != vector.Signature {
		t.Fatal("fixture JWS members do not match top-level values")
	}
	parsed, err := Parse(mustMarshal(t, vector.JWS))
	if err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	protected, payload, signature, err := decodeEncodedComponents(parsed)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if string(protected) != vector.CanonicalProtected || string(payload) != vector.CanonicalClaims {
		t.Fatal("vector does not preserve canonical protected/payload bytes")
	}
	if hex.EncodeToString(signature) != vector.SignatureHex {
		t.Fatal("vector signature hex mismatch")
	}
	if parsed.Protected+"."+parsed.Payload != vector.SigningInput {
		t.Fatal("vector signing input mismatch")
	}
	if !ed25519.Verify(publicKey, []byte(vector.SigningInput), signature) {
		t.Fatal("independent Ed25519 verification failed")
	}
	claims, err := parseCanonicalClaims(payload)
	if err != nil {
		t.Fatalf("parse vector claims: %v", err)
	}
	verified, err := Verify(parsed, VerifyOptions{
		ExpectedIssuer:       claims.Issuer,
		Resolver:             resolverForPublic(ed25519.PublicKey(publicKey), false),
		ExpectedInputDigest:  claims.Input.Value,
		ExpectedOutputDigest: claims.Output.Value,
		ExpectedBinding:      claims.Binding,
	})
	if err != nil {
		t.Fatalf("verify vector: %v", err)
	}
	if !reflect.DeepEqual(verified, claims) {
		t.Fatal("verified claims differ from vector claims")
	}
}

func mustMarshal(t *testing.T, value Signed) []byte {
	t.Helper()
	data, err := Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return data
}
