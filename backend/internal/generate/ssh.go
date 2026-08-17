package generate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

const openSSHPrivateKeyPEMType = "OPENSSH PRIVATE KEY"

// GenerateSSHKeyPair creates one private key and returns its canonical
// OpenSSH serialization and public companion. The public values are derived
// again from the parsed serialization, not retained from key generation.
func (g *Generator) GenerateSSHKeyPair(parameters SSHKeyPairParameters) (SSHKeyPairResult, error) {
	if !validSSHAlgorithm(parameters.Algorithm) {
		return SSHKeyPairResult{}, ErrInvalidParameters
	}
	if g == nil || g.random == nil || g.marshalSSHKey == nil {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}

	privateKey, err := generateSSHPrivateKey(g.random, parameters.Algorithm)
	if err != nil {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	generatedPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}

	block, err := g.marshalSSHKey(privateKey, "")
	if err != nil || block == nil {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	defer clear(block.Bytes)
	if block.Type != openSSHPrivateKeyPEMType || len(block.Bytes) == 0 || len(block.Headers) != 0 {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	privatePEM := pem.EncodeToMemory(block)
	if !hasExactlyOneTerminalLF(privatePEM) {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	defer clear(privatePEM)

	parsed, err := ssh.ParseRawPrivateKey(privatePEM)
	if err != nil {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	parsedSigner, ok := parsed.(crypto.Signer)
	if !ok || !sshPublicKeyMatchesAlgorithm(parsedSigner.Public(), parameters.Algorithm) {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	parsedPublicKey, err := ssh.NewPublicKey(parsedSigner.Public())
	if err != nil || parsedPublicKey.Type() != sshKeyType(parameters.Algorithm) ||
		!bytes.Equal(parsedPublicKey.Marshal(), generatedPublicKey.Marshal()) {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}

	authorizedKeyWithLF := ssh.MarshalAuthorizedKey(parsedPublicKey)
	if !hasExactlyOneTerminalLF(authorizedKeyWithLF) {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}
	authorizedKey := strings.TrimSuffix(string(authorizedKeyWithLF), "\n")
	if authorizedKey == "" || strings.ContainsAny(authorizedKey, "\r\n") {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}

	fingerprint := ssh.FingerprintSHA256(parsedPublicKey)
	if !validSHA256Fingerprint(fingerprint) {
		return SSHKeyPairResult{}, ErrGenerationFailed
	}

	return SSHKeyPairResult{
		private:       newPrivateMaterial(privatePEM),
		algorithm:     parameters.Algorithm,
		authorizedKey: authorizedKey,
		fingerprint:   fingerprint,
	}, nil
}

func validSSHAlgorithm(algorithm SSHAlgorithm) bool {
	switch algorithm {
	case SSHAlgorithmEd25519, SSHAlgorithmECDSAP256, SSHAlgorithmRSA3072, SSHAlgorithmRSA4096:
		return true
	default:
		return false
	}
}

func generateSSHPrivateKey(random io.Reader, algorithm SSHAlgorithm) (crypto.Signer, error) {
	switch algorithm {
	case SSHAlgorithmEd25519:
		_, privateKey, err := ed25519.GenerateKey(random)
		return privateKey, err
	case SSHAlgorithmECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), random)
	case SSHAlgorithmRSA3072:
		return rsa.GenerateKey(random, 3072)
	case SSHAlgorithmRSA4096:
		return rsa.GenerateKey(random, 4096)
	default:
		return nil, ErrInvalidParameters
	}
}

func sshPublicKeyMatchesAlgorithm(publicKey crypto.PublicKey, algorithm SSHAlgorithm) bool {
	switch algorithm {
	case SSHAlgorithmEd25519:
		key, ok := publicKey.(ed25519.PublicKey)
		return ok && len(key) == ed25519.PublicKeySize
	case SSHAlgorithmECDSAP256:
		key, ok := publicKey.(*ecdsa.PublicKey)
		return ok && key.Curve != nil && key.Curve.Params() != nil && key.Curve.Params().Name == elliptic.P256().Params().Name
	case SSHAlgorithmRSA3072:
		key, ok := publicKey.(*rsa.PublicKey)
		return ok && key.N != nil && key.N.BitLen() == 3072
	case SSHAlgorithmRSA4096:
		key, ok := publicKey.(*rsa.PublicKey)
		return ok && key.N != nil && key.N.BitLen() == 4096
	default:
		return false
	}
}

func sshKeyType(algorithm SSHAlgorithm) string {
	switch algorithm {
	case SSHAlgorithmEd25519:
		return ssh.KeyAlgoED25519
	case SSHAlgorithmECDSAP256:
		return ssh.KeyAlgoECDSA256
	case SSHAlgorithmRSA3072, SSHAlgorithmRSA4096:
		return ssh.KeyAlgoRSA
	default:
		return ""
	}
}

func hasExactlyOneTerminalLF(value []byte) bool {
	return len(value) > 0 && value[len(value)-1] == '\n' && (len(value) == 1 || value[len(value)-2] != '\n')
}

func validSHA256Fingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) || strings.ContainsRune(value, '=') {
		return false
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(digest) == 32 && prefix+base64.RawStdEncoding.EncodeToString(digest) == value
}
