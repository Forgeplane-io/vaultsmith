package ansiblevault

import (
	"bytes"
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

func TestReencrypt(t *testing.T) {
	sourcePassword := []byte("source-password")
	destinationPassword := []byte("destination-password")
	fixture := []byte("fixture-value")

	source11, err := encryptWithHeader(fixture, sourcePassword, Header11)
	if err != nil {
		t.Fatalf("encrypt source Vault 1.1: %v", err)
	}
	source12, err := Encrypt(fixture, sourcePassword, "source")
	if err != nil {
		t.Fatalf("encrypt source Vault 1.2: %v", err)
	}

	for _, tc := range []struct {
		name     string
		input    string
		source   []byte
		dest     []byte
		destID   string
		wantErr  error
		wantBody string
	}{
		{name: "Vault 1.1 to labeled 1.2", input: source11, source: sourcePassword, dest: destinationPassword, destID: "destination", wantBody: string(fixture)},
		{name: "labeled Vault 1.2 to labeled 1.2", input: source12, source: sourcePassword, dest: destinationPassword, destID: "destination", wantBody: string(fixture)},
		{name: "same profile format upgrade", input: source11, source: sourcePassword, dest: sourcePassword, destID: "source", wantBody: string(fixture)},
		{name: "wrong source password", input: source11, source: []byte("wrong-password"), dest: destinationPassword, destID: "destination", wantErr: ErrInvalidVault},
		{name: "invalid destination password", input: source11, source: sourcePassword, dest: nil, destID: "destination", wantErr: ErrInvalidPassword},
		{name: "invalid destination label", input: source11, source: sourcePassword, dest: destinationPassword, destID: "destination;other", wantErr: ErrInvalidVaultID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Reencrypt(tc.input, tc.source, tc.dest, tc.destID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Reencrypt() error = %v, want %v", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("Reencrypt() returned ciphertext on error: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reencrypt() error = %v", err)
			}
			if !strings.HasPrefix(got, Header12Prefix+";"+tc.destID+"\n") {
				t.Fatalf("header = %q, want destination label %q", strings.SplitN(got, "\n", 2)[0], tc.destID)
			}
			decoded, err := Decrypt(got, tc.dest)
			if err != nil {
				t.Fatalf("Decrypt() rotated value: %v", err)
			}
			if string(decoded) != tc.wantBody {
				t.Fatalf("rotated plaintext = %q, want %q", decoded, tc.wantBody)
			}
		})
	}
}

func TestReencryptRejectsOversizedPlaintext(t *testing.T) {
	sourcePassword := []byte("source-password")
	input, err := encryptWithHeader(bytes.Repeat([]byte("x"), MaxPlaintextBytes+1), sourcePassword, Header11)
	if err != nil {
		t.Fatalf("encrypt oversized source: %v", err)
	}
	if _, err := Reencrypt(input, sourcePassword, []byte("destination-password"), "destination"); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("Reencrypt() error = %v, want ErrPlaintextTooLarge", err)
	}
}

func TestReencryptRejectsNonUTF8Plaintext(t *testing.T) {
	input, err := encryptWithHeader([]byte{0xff, 0xfe, 0xfd}, []byte("source-password"), Header11)
	if err != nil {
		t.Fatalf("encrypt non-UTF-8 source: %v", err)
	}
	_, err = Reencrypt(input, []byte("source-password"), []byte("destination-password"), "destination")
	if !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("Reencrypt() error = %v, want ErrInvalidVault", err)
	}
	if strings.Contains(err.Error(), "fffe fd") {
		t.Fatalf("Reencrypt() error exposed plaintext bytes: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
