package generate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateSSHKeyPairProducesMatchingOpenSSHArtifacts(t *testing.T) {
	tests := []struct {
		name      string
		algorithm SSHAlgorithm
		keyType   string
	}{
		{name: "Ed25519", algorithm: SSHAlgorithmEd25519, keyType: ssh.KeyAlgoED25519},
		{name: "ECDSA P-256", algorithm: SSHAlgorithmECDSAP256, keyType: ssh.KeyAlgoECDSA256},
		{name: "RSA-3072", algorithm: SSHAlgorithmRSA3072, keyType: ssh.KeyAlgoRSA},
		{name: "RSA-4096", algorithm: SSHAlgorithmRSA4096, keyType: ssh.KeyAlgoRSA},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := New().GenerateSSHKeyPair(SSHKeyPairParameters{Algorithm: test.algorithm})
			if err != nil {
				t.Fatalf("GenerateSSHKeyPair() error = %v", err)
			}
			if result.Algorithm() != test.algorithm {
				t.Fatalf("algorithm = %q, want %q", result.Algorithm(), test.algorithm)
			}

			privatePEM := result.PrivateBytes()
			if !hasExactlyOneTerminalLF(privatePEM) {
				t.Fatalf("private key does not have exactly one terminal LF")
			}
			block, rest := pem.Decode(privatePEM)
			if block == nil || block.Type != openSSHPrivateKeyPEMType || len(block.Headers) != 0 || len(rest) != 0 {
				t.Fatalf("private PEM block = %#v, trailing bytes = %d", block, len(rest))
			}

			parsedPrivate, err := ssh.ParseRawPrivateKey(privatePEM)
			if err != nil {
				t.Fatalf("ParseRawPrivateKey() error = %v", err)
			}
			privateSigner, ok := parsedPrivate.(crypto.Signer)
			if !ok {
				t.Fatalf("parsed private key does not implement crypto.Signer")
			}
			assertSSHPrivateAlgorithm(t, privateSigner, test.algorithm)

			privatePublic, err := ssh.NewPublicKey(privateSigner.Public())
			if err != nil {
				t.Fatalf("NewPublicKey(parsed private) error = %v", err)
			}
			if privatePublic.Type() != test.keyType {
				t.Fatalf("public key type = %q, want %q", privatePublic.Type(), test.keyType)
			}

			authorizedText := result.AuthorizedKey()
			if authorizedText == "" || bytes.ContainsAny([]byte(authorizedText), "\r\n") {
				t.Fatalf("authorized key has invalid line endings")
			}
			authorizedPublic, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(authorizedText + "\n"))
			if err != nil {
				t.Fatalf("ParseAuthorizedKey() error = %v", err)
			}
			if comment != "" || len(options) != 0 || len(rest) != 0 {
				t.Fatalf("authorized key comment/options/rest = %q/%v/%d", comment, options, len(rest))
			}
			if !bytes.Equal(authorizedPublic.Marshal(), privatePublic.Marshal()) {
				t.Fatal("authorized key does not match serialized private key")
			}
			if got := string(ssh.MarshalAuthorizedKey(authorizedPublic)); got != authorizedText+"\n" {
				t.Fatalf("authorized key is not canonical: %q", got)
			}
			if got := ssh.FingerprintSHA256(authorizedPublic); result.Fingerprint() != got {
				t.Fatalf("fingerprint = %q, want %q", result.Fingerprint(), got)
			}
		})
	}
}

func TestGenerateSSHKeyPairFailsClosed(t *testing.T) {
	sensitiveFailure := errors.New("sensitive randomness detail")
	randomFailure := New()
	randomFailure.random = sshErrorReader{err: sensitiveFailure}
	result, err := randomFailure.GenerateSSHKeyPair(SSHKeyPairParameters{Algorithm: SSHAlgorithmEd25519})
	if !errors.Is(err, ErrGenerationFailed) || errors.Is(err, sensitiveFailure) || !emptySSHResult(result) {
		t.Fatalf("random failure result/error = %#v/%v", result, err)
	}

	marshalFailure := New()
	marshalFailure.marshalSSHKey = func(crypto.PrivateKey, string) (*pem.Block, error) {
		return nil, sensitiveFailure
	}
	result, err = marshalFailure.GenerateSSHKeyPair(SSHKeyPairParameters{Algorithm: SSHAlgorithmEd25519})
	if !errors.Is(err, ErrGenerationFailed) || errors.Is(err, sensitiveFailure) || !emptySSHResult(result) {
		t.Fatalf("marshal failure result/error = %#v/%v", result, err)
	}

	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(test mismatch) error = %v", err)
	}
	otherBlock, err := ssh.MarshalPrivateKey(otherPrivate, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey(test mismatch) error = %v", err)
	}
	mismatch := New()
	mismatch.marshalSSHKey = func(crypto.PrivateKey, string) (*pem.Block, error) {
		return otherBlock, nil
	}
	result, err = mismatch.GenerateSSHKeyPair(SSHKeyPairParameters{Algorithm: SSHAlgorithmEd25519})
	if !errors.Is(err, ErrGenerationFailed) || !emptySSHResult(result) {
		t.Fatalf("mismatched serialization result/error = %#v/%v", result, err)
	}
}

func TestGenerateSSHKeyPairRejectsUnsupportedAlgorithmBeforeRandomness(t *testing.T) {
	source := &sshCountingReader{}
	generator := New()
	generator.random = source
	result, err := generator.GenerateSSHKeyPair(SSHKeyPairParameters{Algorithm: "dsa"})
	if !errors.Is(err, ErrInvalidParameters) || source.calls != 0 || !emptySSHResult(result) {
		t.Fatalf("unsupported algorithm result/error/random calls = %#v/%v/%d", result, err, source.calls)
	}
}

func assertSSHPrivateAlgorithm(t *testing.T, signer crypto.Signer, algorithm SSHAlgorithm) {
	t.Helper()
	switch algorithm {
	case SSHAlgorithmEd25519:
		key, ok := signer.Public().(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			t.Fatalf("Ed25519 public key = %T/%d bytes", signer.Public(), len(key))
		}
	case SSHAlgorithmECDSAP256:
		key, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok || key.Curve == nil || key.Curve.Params().Name != elliptic.P256().Params().Name {
			t.Fatalf("ECDSA public key = %T", signer.Public())
		}
	case SSHAlgorithmRSA3072, SSHAlgorithmRSA4096:
		key, ok := signer.Public().(*rsa.PublicKey)
		if !ok {
			t.Fatalf("RSA public key = %T", signer.Public())
		}
		wantBits := 3072
		if algorithm == SSHAlgorithmRSA4096 {
			wantBits = 4096
		}
		if key.N.BitLen() != wantBits {
			t.Fatalf("RSA modulus = %d bits, want %d", key.N.BitLen(), wantBits)
		}
	default:
		t.Fatalf("unhandled test algorithm %q", algorithm)
	}
}

func emptySSHResult(result SSHKeyPairResult) bool {
	return len(result.PrivateBytes()) == 0 && result.Algorithm() == "" && result.AuthorizedKey() == "" && result.Fingerprint() == ""
}

type sshErrorReader struct {
	err error
}

func (r sshErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type sshCountingReader struct {
	calls int
}

func (r *sshCountingReader) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("unexpected randomness request")
}
