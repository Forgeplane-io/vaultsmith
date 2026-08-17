package generate

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestGenerateAgeIdentityProducesMatchingNativeArtifacts(t *testing.T) {
	result, err := New().GenerateAgeIdentity()
	if err != nil {
		t.Fatalf("GenerateAgeIdentity() error = %v", err)
	}

	privateBytes := result.PrivateBytes()
	if !hasExactlyOneTerminalLF(privateBytes) {
		t.Fatal("age identity does not have exactly one terminal LF")
	}
	identityText := strings.TrimSuffix(string(privateBytes), "\n")
	if !strings.HasPrefix(identityText, "AGE-SECRET-KEY-1") || identityText != strings.ToUpper(identityText) {
		t.Fatalf("identity is not canonical native age text")
	}
	identity, err := age.ParseX25519Identity(identityText)
	if err != nil {
		t.Fatalf("ParseX25519Identity() error = %v", err)
	}
	if identity.String() != identityText {
		t.Fatalf("identity canonical form changed")
	}

	recipientText := result.Recipient()
	if strings.ContainsAny(recipientText, "\r\n") || !strings.HasPrefix(recipientText, "age1") {
		t.Fatalf("recipient is not one canonical line")
	}
	recipient, err := age.ParseX25519Recipient(recipientText)
	if err != nil {
		t.Fatalf("ParseX25519Recipient() error = %v", err)
	}
	if recipient.String() != recipientText || identity.Recipient().String() != recipientText {
		t.Fatal("recipient does not match serialized private identity")
	}

	plaintext := []byte("synthetic age interoperability check")
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt() error = %v", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatalf("age writer error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("age writer close error = %v", err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), identity)
	if err != nil {
		t.Fatalf("age.Decrypt() error = %v", err)
	}
	decrypted, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("age plaintext read error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", decrypted, plaintext)
	}
}

func TestGenerateAgeIdentityFailsClosed(t *testing.T) {
	sensitiveFailure := errors.New("sensitive age failure detail")
	generationFailure := New()
	generationFailure.ageIdentity = func() (string, string, error) {
		return "AGE-SECRET-KEY-private", "age1public", sensitiveFailure
	}
	result, err := generationFailure.GenerateAgeIdentity()
	if !errors.Is(err, ErrGenerationFailed) || errors.Is(err, sensitiveFailure) || !emptyAgeResult(result) {
		t.Fatalf("generation failure result/error = %#v/%v", result, err)
	}

	first, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity(first) error = %v", err)
	}
	second, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity(second) error = %v", err)
	}
	mismatch := New()
	mismatch.ageIdentity = func() (string, string, error) {
		return first.String(), second.Recipient().String(), nil
	}
	result, err = mismatch.GenerateAgeIdentity()
	if !errors.Is(err, ErrGenerationFailed) || !emptyAgeResult(result) {
		t.Fatalf("recipient mismatch result/error = %#v/%v", result, err)
	}
}

func emptyAgeResult(result AgeIdentityResult) bool {
	return len(result.PrivateBytes()) == 0 && result.Recipient() == ""
}
