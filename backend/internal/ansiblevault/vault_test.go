package ansiblevault

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	password := []byte("synthetic-password")
	cases := []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: []byte{}},
		{name: "short", value: []byte("fixture-value")},
		{name: "unicode", value: []byte("Grüße from Vaultsmith 🔐")},
		{name: "block boundary", value: []byte(strings.Repeat("x", 32))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Encrypt(tc.value, password, "dev")
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			if !strings.HasPrefix(encoded, Header12Prefix+";dev\n") {
				t.Fatalf("encrypted value does not start with Vault header: %q", encoded[:min(len(encoded), 64)])
			}
			decoded, err := Decrypt(encoded, password)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if string(decoded) != string(tc.value) {
				t.Fatalf("round trip = %q, want %q", decoded, tc.value)
			}
		})
	}
}

func TestEncryptUsesFreshSalt(t *testing.T) {
	first, err := Encrypt([]byte("same"), []byte("password"), "dev")
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}
	second, err := Encrypt([]byte("same"), []byte("password"), "dev")
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}
	if first == second {
		t.Fatal("two encryptions unexpectedly produced identical ciphertext")
	}
}

func TestEncryptShape(t *testing.T) {
	encoded, err := Encrypt([]byte("fixture-value"), []byte("password"), "dev")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(encoded, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("encrypted value has %d lines, want at least 2", len(lines))
	}
	if lines[0] != Header12Prefix+";dev" {
		t.Fatalf("header = %q, want %q", lines[0], Header12Prefix+";dev")
	}
	for index, line := range lines[1:] {
		if len(line) == 0 || len(line) > 80 {
			t.Fatalf("body line %d length = %d, want 1..80", index, len(line))
		}
	}
}

func TestDecryptRejectsWrongPassword(t *testing.T) {
	encoded, err := Encrypt([]byte("fixture-value"), []byte("correct"), "dev")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if _, err := Decrypt(encoded, []byte("incorrect")); err == nil {
		t.Fatal("Decrypt() with wrong password unexpectedly succeeded")
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	encoded, err := Encrypt([]byte("fixture-value"), []byte("password"), "dev")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	body := []byte(encoded)
	for index := len(body) - 1; index >= 0; index-- {
		if body[index] >= '0' && body[index] <= '8' {
			body[index]++
			break
		}
		if body[index] >= '9' {
			body[index] = '0'
			break
		}
	}
	if _, err := Decrypt(string(body), []byte("password")); err == nil {
		t.Fatal("Decrypt() of tampered ciphertext unexpectedly succeeded")
	}
}

func TestRejectsInvalidPasswords(t *testing.T) {
	if _, err := Encrypt([]byte("value"), nil, "dev"); err == nil {
		t.Fatal("Encrypt() with empty password unexpectedly succeeded")
	}
	if _, err := Decrypt("", nil); err == nil {
		t.Fatal("Decrypt() with empty password unexpectedly succeeded")
	}
}

func TestDecryptRejectsMalformedVaultText(t *testing.T) {
	cases := []string{
		"",
		"$ANSIBLE_VAULT;1.2;AES256\n00",
		Header11 + "\nnot-hex",
		Header11 + "\n" + strings.Repeat("0", 80) + "\n" + strings.Repeat("0", 80),
	}
	for _, input := range cases {
		t.Run(strings.ReplaceAll(input, "\n", "_"), func(t *testing.T) {
			if _, err := Decrypt(input, []byte("password")); err == nil {
				t.Fatal("Decrypt() unexpectedly accepted malformed Vault text")
			}
		})
	}
}

func TestRejectsInvalidVaultIDs(t *testing.T) {
	for _, vaultID := range []string{"", " dev", "dev ", "dev;prod", "dev\nprod"} {
		t.Run(strings.ReplaceAll(vaultID, "\n", "_"), func(t *testing.T) {
			_, err := Encrypt([]byte("value"), []byte("password"), vaultID)
			if !errors.Is(err, ErrInvalidVaultID) {
				t.Fatalf("Encrypt() error = %v, want ErrInvalidVaultID", err)
			}
		})
	}
}

func TestDecryptAcceptsUnlabeledVault12(t *testing.T) {
	encoded, err := Encrypt([]byte("fixture-value"), []byte("password"), "dev")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	body := strings.SplitN(encoded, "\n", 2)[1]
	decoded, err := Decrypt(Header12Prefix+"\n"+body, []byte("password"))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(decoded) != "fixture-value" {
		t.Fatalf("decoded value = %q, want %q", decoded, "fixture-value")
	}
}

func TestDecryptAnsibleCLIStaticFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/ansible-vault-1.1.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	plaintext, err := Decrypt(string(fixture), []byte("fixture-password"))
	if err != nil {
		t.Fatalf("Decrypt() fixture error = %v", err)
	}
	if string(plaintext) != "fixture-value" {
		t.Fatalf("fixture plaintext = %q, want %q", plaintext, "fixture-value")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
