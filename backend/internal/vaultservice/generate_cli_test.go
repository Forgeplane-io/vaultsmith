//go:build ansible_cli

package vaultservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/generate"
	"golang.org/x/crypto/ssh"
)

// Match the server's adapter without replacing profile encryption with a fake.
type cliProfileResolver struct{ configured config.Executor }

func (r cliProfileResolver) ForProfile(profileID string) (ProfileExecutor, error) {
	return r.configured.ForProfile(profileID)
}

func TestCLIGeneratedPrivateFormats(t *testing.T) {
	binary := os.Getenv("ANSIBLE_VAULT_BIN")
	if binary == "" {
		binary = "ansible-vault"
	}
	binary, err := exec.LookPath(binary)
	if err != nil {
		t.Fatal("ansible-vault CLI prerequisite missing; install ansible-core or set ANSIBLE_VAULT_BIN")
	}

	const vaultPassword = "synthetic-cli-qualification-password"
	configured, err := config.LoadJSON(`[{"id":"dev","label":"Synthetic CLI qualification","passwordEnv":"TEST_VAULT_PASSWORD"}]`, func(name string) (string, bool) {
		return vaultPassword, name == "TEST_VAULT_PASSWORD"
	})
	if err != nil {
		t.Fatal("load synthetic destination profile")
	}
	base64Encoding, hexEncoding := generate.TokenEncodingBase64URL, generate.TokenEncodingHex
	type qualificationCase struct {
		name    string
		command GenerateCommand
	}
	tests := []qualificationCase{
		{"password", GenerateCommand{Kind: GenerateKindPassword, Password: &generate.PasswordParameters{}}},
		{"token/base64url", GenerateCommand{Kind: GenerateKindToken, Token: &generate.TokenParameters{Encoding: &base64Encoding}}},
		{"token/hex", GenerateCommand{Kind: GenerateKindToken, Token: &generate.TokenParameters{Encoding: &hexEncoding}}},
		{"age/x25519", GenerateCommand{Kind: GenerateKindAgeIdentity, AgeIdentity: &AgeIdentityParameters{}}},
	}
	for _, algorithm := range []generate.SSHAlgorithm{generate.SSHAlgorithmEd25519, generate.SSHAlgorithmECDSAP256, generate.SSHAlgorithmRSA3072, generate.SSHAlgorithmRSA4096} {
		tests = append(tests, qualificationCase{"ssh/" + string(algorithm), GenerateCommand{Kind: GenerateKindSSHKeyPair, SSHKeyPair: &generate.SSHKeyPairParameters{Algorithm: algorithm}}})
	}
	for _, algorithm := range []generate.X509Algorithm{generate.X509AlgorithmEd25519, generate.X509AlgorithmECDSAP256, generate.X509AlgorithmECDSAP384, generate.X509AlgorithmRSA3072, generate.X509AlgorithmRSA4096} {
		tests = append(tests, qualificationCase{"x509/" + string(algorithm), GenerateCommand{Kind: GenerateKindX509CSR, X509CSR: &generate.X509CSRParameters{
			Algorithm: algorithm,
			SANs:      &generate.X509SANs{DNSNames: []string{"service.synthetic.test"}},
		}}})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			t.Cleanup(func() { clear(generator.lastPrivate) })
			admission := testAdmission(t)
			service := NewWithOptions([]Profile{{ID: "dev", Label: "Synthetic CLI qualification"}}, cliProfileResolver{configured.Executor()}, nil, admission, ServiceOptions{Generator: generator})
			lease := acquireLease(t, admission)
			test.command.ProfileID = "dev"
			result, err := service.Generate(lease.Context(t.Context()), caller.Anonymous(), test.command)
			if err != nil {
				t.Fatal("Generate failed")
			}
			secret := result.SealedSecret()
			if result.MaterialKind() != test.command.Kind || result.DestinationProfileID() != "dev" || !strings.HasPrefix(secret.VaultText, ansiblevault.Header12Prefix+";dev\n") {
				t.Fatal("generated result identity or Vault 1.2/AES256 destination label differs")
			}
			workspace := t.TempDir()
			passwordPath := filepath.Join(workspace, "password.txt")
			encryptedPath := filepath.Join(workspace, "encrypted.txt")
			decryptedPath := filepath.Join(workspace, "decrypted.txt")
			if err := os.WriteFile(passwordPath, []byte(vaultPassword), 0o600); err != nil {
				t.Fatal("write synthetic password file")
			}
			if err := os.WriteFile(encryptedPath, []byte(secret.VaultText), 0o600); err != nil {
				t.Fatal("write generated Vault file")
			}
			// Like the basic CLI harness, never include CLI output or file contents in diagnostics.
			command := exec.CommandContext(t.Context(), binary, "decrypt", "--vault-id", "dev@"+passwordPath, "--output", decryptedPath, encryptedPath)
			command.Stdout, command.Stderr = io.Discard, io.Discard
			if err := command.Run(); err != nil {
				t.Fatal("ansible-vault decrypt failed")
			}
			private, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Fatal("read CLI-recovered private serialization")
			}
			defer clear(private)
			if !bytes.Equal(private, generator.lastPrivate) {
				t.Fatal("CLI-recovered bytes differ from exact generated private serialization")
			}
			checkCLIGeneratedMaterial(t, private, result, test.command)
		})
	}
}

func checkCLIGeneratedMaterial(t *testing.T, private []byte, result GenerateResult, command GenerateCommand) {
	t.Helper()
	switch result := result.(type) {
	case GeneratedPasswordResult:
		if result.Secret.Format != generate.PasswordFormat || len(private) != result.EffectiveParameters.Length {
			t.Fatal("password format or length differs")
		}
		for _, char := range private {
			if char < '!' || char > '~' {
				t.Fatal("password is not printable ASCII without a terminal newline")
			}
		}
	case GeneratedTokenResult:
		var decoded []byte
		var canonical string
		var err error
		switch result.EffectiveParameters.Encoding {
		case generate.TokenEncodingBase64URL:
			if result.Secret.Format != generate.TokenBase64Format {
				t.Fatal("base64url token format differs")
			}
			decoded, err = base64.RawURLEncoding.Strict().DecodeString(string(private))
			canonical = base64.RawURLEncoding.EncodeToString(decoded)
		case generate.TokenEncodingHex:
			if result.Secret.Format != generate.TokenHexFormat {
				t.Fatal("hex token format differs")
			}
			decoded, err = hex.DecodeString(string(private))
			canonical = hex.EncodeToString(decoded)
		default:
			t.Fatal("unsupported token encoding")
		}
		defer clear(decoded)
		if result.EffectiveParameters.Encoding != *command.Token.Encoding || err != nil || len(decoded) != result.EffectiveParameters.Bytes || canonical != string(private) {
			t.Fatal("token encoding, decoded length, or canonical serialization differs")
		}
	case GeneratedSSHKeyPairResult:
		if result.Secret.Format != generate.SSHPrivateFormat || result.Public.Format != generate.SSHPublicFormat || result.Algorithm != command.SSHKeyPair.Algorithm {
			t.Fatal("SSH formats or algorithm differ")
		}
		parseCLIPEM(t, private, "OPENSSH PRIVATE KEY")
		key, err := ssh.ParseRawPrivateKey(private)
		if err != nil {
			t.Fatal("parse CLI-recovered unencrypted OpenSSH private key")
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("SSH private key is not a signer")
		}
		checkCLIKeyAlgorithm(t, signer.Public(), string(result.Algorithm))
		public, err := ssh.NewPublicKey(signer.Public())
		if err != nil || string(ssh.MarshalAuthorizedKey(public)) != result.Public.AuthorizedKey+"\n" || ssh.FingerprintSHA256(public) != result.Public.Fingerprint {
			t.Fatal("SSH authorized key or fingerprint differs from recovered private key")
		}
	case GeneratedAgeIdentityResult:
		if result.Secret.Format != generate.AgePrivateFormat || result.Public.Format != generate.AgePublicFormat || result.Algorithm != "x25519" {
			t.Fatal("age formats or algorithm differ")
		}
		identity, err := age.ParseX25519Identity(strings.TrimSuffix(string(private), "\n"))
		if err != nil {
			t.Fatal("parse CLI-recovered native age identity")
		}
		recipient, err := age.ParseX25519Recipient(result.Public.Recipient)
		if err != nil || identity.String()+"\n" != string(private) || identity.Recipient().String() != recipient.String() || recipient.String() != result.Public.Recipient {
			t.Fatal("age canonical serialization or recipient differs from recovered identity")
		}
	case GeneratedX509CSRResult:
		if result.Secret.Format != generate.X509PrivateFormat || result.Public.Format != generate.X509PublicFormat || result.Algorithm != command.X509CSR.Algorithm {
			t.Fatal("X.509 formats or algorithm differ")
		}
		block := parseCLIPEM(t, private, "PRIVATE KEY")
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal("parse CLI-recovered unencrypted PKCS#8 private key")
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("PKCS#8 private key is not a signer")
		}
		checkCLIKeyAlgorithm(t, signer.Public(), string(result.Algorithm))
		canonical, err := x509.MarshalPKCS8PrivateKey(key)
		defer clear(canonical)
		if err != nil || !bytes.Equal(canonical, block.Bytes) {
			t.Fatal("PKCS#8 private serialization is not canonical")
		}
		csrBlock := parseCLIPEM(t, []byte(result.Public.CSRPEM), "CERTIFICATE REQUEST")
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			t.Fatal("parse generated PKCS#10 CSR")
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatal("verify generated CSR signature")
		}
		spki, err := x509.MarshalPKIXPublicKey(signer.Public())
		digest := sha256.Sum256(spki)
		if err != nil || !bytes.Equal(spki, csr.RawSubjectPublicKeyInfo) || result.Public.Fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:]) || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "service.synthetic.test" {
			t.Fatal("CSR public key, fingerprint, or synthetic DNS SAN differs")
		}
	default:
		t.Fatal("unhandled generated result kind")
	}
}

func parseCLIPEM(t *testing.T, value []byte, expectedType string) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(value)
	if block == nil || block.Type != expectedType || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(pem.EncodeToMemory(block), value) {
		t.Fatal("PEM type or canonical serialization with one terminal LF differs")
	}
	return block
}

func checkCLIKeyAlgorithm(t *testing.T, public crypto.PublicKey, algorithm string) {
	t.Helper()
	switch algorithm {
	case "ed25519":
		key, ok := public.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			t.Fatal("recovered key is not Ed25519")
		}
	case "ecdsa_p256", "ecdsa_p384":
		curve := elliptic.P256()
		if algorithm == "ecdsa_p384" {
			curve = elliptic.P384()
		}
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve != curve {
			t.Fatal("recovered key has the wrong ECDSA curve")
		}
	case "rsa_3072", "rsa_4096":
		bits := 3072
		if algorithm == "rsa_4096" {
			bits = 4096
		}
		key, ok := public.(*rsa.PublicKey)
		if !ok || key.N.BitLen() != bits {
			t.Fatal("recovered key has the wrong RSA modulus size")
		}
	default:
		t.Fatal("unhandled key algorithm")
	}
}
