//go:build ansible_cli

package ansiblevault

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIDecryptsGoOutput(t *testing.T) {
	binary := ansibleVaultBinary(t)
	workspace := t.TempDir()
	passwordPath := filepath.Join(workspace, "password.txt")
	encryptedPath := filepath.Join(workspace, "encrypted.txt")
	decryptedPath := filepath.Join(workspace, "decrypted.txt")
	if err := os.WriteFile(passwordPath, []byte("cli-password"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	encoded, err := Encrypt([]byte("go-to-cli"), []byte("cli-password"), "dev")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if err := os.WriteFile(encryptedPath, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write encrypted file: %v", err)
	}

	runCLI(t, binary, "decrypt", "--vault-password-file", passwordPath, "--output", decryptedPath, encryptedPath)
	plaintext, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read CLI plaintext: %v", err)
	}
	if string(plaintext) != "go-to-cli" {
		t.Fatalf("CLI plaintext = %q, want %q", plaintext, "go-to-cli")
	}
}

func TestCLIVaultOutputDecryptsInGo(t *testing.T) {
	binary := ansibleVaultBinary(t)
	workspace := t.TempDir()
	passwordPath := filepath.Join(workspace, "password.txt")
	plaintextPath := filepath.Join(workspace, "plaintext.txt")
	encryptedPath := filepath.Join(workspace, "encrypted.txt")
	if err := os.WriteFile(passwordPath, []byte("cli-password"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	if err := os.WriteFile(plaintextPath, []byte("cli-to-go"), 0o600); err != nil {
		t.Fatalf("write plaintext file: %v", err)
	}

	runCLI(t, binary, "encrypt", "--vault-password-file", passwordPath, "--output", encryptedPath, plaintextPath)
	vaultText, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read CLI ciphertext: %v", err)
	}
	plaintext, err := Decrypt(string(vaultText), []byte("cli-password"))
	if err != nil {
		t.Fatalf("Decrypt() CLI output error = %v", err)
	}
	if string(plaintext) != "cli-to-go" {
		t.Fatalf("Go plaintext = %q, want %q", plaintext, "cli-to-go")
	}
}

func TestCLILabeledVaultOutputDecryptsInGo(t *testing.T) {
	binary := ansibleVaultBinary(t)
	workspace := t.TempDir()
	passwordPath := filepath.Join(workspace, "password.txt")
	plaintextPath := filepath.Join(workspace, "plaintext.txt")
	encryptedPath := filepath.Join(workspace, "encrypted.txt")
	if err := os.WriteFile(passwordPath, []byte("cli-password"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	if err := os.WriteFile(plaintextPath, []byte("cli-labeled-to-go"), 0o600); err != nil {
		t.Fatalf("write plaintext file: %v", err)
	}

	runCLI(t, binary, "encrypt", "--vault-id", "dev@"+passwordPath, "--output", encryptedPath, plaintextPath)
	vaultText, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read labeled CLI ciphertext: %v", err)
	}
	if !strings.HasPrefix(string(vaultText), "$ANSIBLE_VAULT;1.2;AES256;dev\n") {
		t.Fatalf("CLI labeled header = %q, want Vault 1.2 label", strings.SplitN(string(vaultText), "\n", 2)[0])
	}
	plaintext, err := Decrypt(string(vaultText), []byte("cli-password"))
	if err != nil {
		t.Fatalf("Decrypt() labeled CLI output error = %v", err)
	}
	if string(plaintext) != "cli-labeled-to-go" {
		t.Fatalf("Go plaintext = %q, want %q", plaintext, "cli-labeled-to-go")
	}
}

func ansibleVaultBinary(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("ANSIBLE_VAULT_BIN"); configured != "" {
		if _, err := os.Stat(configured); err != nil {
			t.Fatalf("ANSIBLE_VAULT_BIN=%q is not executable: %v", configured, err)
		}
		return configured
	}
	binary, err := exec.LookPath("ansible-vault")
	if err != nil {
		t.Fatalf("ansible-vault CLI prerequisite missing; set ANSIBLE_VAULT_BIN or install ansible-core: %v", err)
	}
	return binary
}

func runCLI(t *testing.T, binary string, args ...string) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Fatalf("ansible-vault %v failed: %v", args[:1], err)
	}
}
