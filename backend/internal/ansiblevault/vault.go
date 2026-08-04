package ansiblevault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Header11          = "$ANSIBLE_VAULT;1.1;AES256"
	Header12Prefix    = "$ANSIBLE_VAULT;1.2;AES256"
	pbkdf2Iterations  = 10000
	saltSize          = 32
	derivedKeySize    = 80
	keySize           = 32
	macSize           = 32
	ivSize            = 16
	lineWidth         = 80
	MaxPlaintextBytes = 1 << 20
)

var (
	ErrInvalidPassword   = errors.New("invalid vault password")
	ErrInvalidVault      = errors.New("invalid vault text")
	ErrInvalidVaultID    = errors.New("invalid vault ID")
	ErrPlaintextTooLarge = errors.New("plaintext is too large")
)

// Encrypt encodes plaintext using the Ansible Vault 1.2/AES256 format with a
// vault ID label. It intentionally returns a new salt for every invocation.
func Encrypt(plaintext, password []byte, vaultID string) (string, error) {
	return EncryptWithVaultID(plaintext, password, vaultID)
}

// EncryptWithVaultID encodes plaintext using Ansible Vault 1.2/AES256 with a
// vault ID label in the header. The label is metadata; the selected password
// still determines the encryption key.
func EncryptWithVaultID(plaintext, password []byte, vaultID string) (string, error) {
	if err := ValidateVaultID(vaultID); err != nil {
		return "", err
	}
	return encryptWithHeader(plaintext, password, Header12Prefix+";"+vaultID)
}

// ValidateVaultID checks the header-safe label used by Ansible Vault 1.2.
func ValidateVaultID(vaultID string) error {
	if vaultID == "" || strings.TrimSpace(vaultID) != vaultID || strings.ContainsAny(vaultID, ";\r\n") {
		return ErrInvalidVaultID
	}
	return nil
}

func encryptWithHeader(plaintext, password []byte, header string) (string, error) {
	if len(password) == 0 {
		return "", ErrInvalidPassword
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	keyMaterial := derive(password, salt)
	key := keyMaterial[:keySize]
	macKey := keyMaterial[keySize : keySize+macSize]
	iv := keyMaterial[keySize+macSize : keySize+macSize+ivSize]

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	stream, err := newCTR(key, iv)
	if err != nil {
		return "", err
	}
	stream.XORKeyStream(ciphertext, padded)

	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(ciphertext)

	inner := strings.Join([]string{
		hex.EncodeToString(salt),
		hex.EncodeToString(mac.Sum(nil)),
		hex.EncodeToString(ciphertext),
	}, "\n")
	body := hex.EncodeToString([]byte(inner))

	var out strings.Builder
	out.Grow(len(header) + 1 + len(body) + len(body)/lineWidth + 1)
	out.WriteString(header)
	out.WriteByte('\n')
	for len(body) > lineWidth {
		out.WriteString(body[:lineWidth])
		out.WriteByte('\n')
		body = body[lineWidth:]
	}
	out.WriteString(body)
	out.WriteByte('\n')
	return out.String(), nil
}

// Decrypt decodes an Ansible Vault 1.1 or 1.2/AES256 value. All malformed input and
// authentication failures intentionally collapse to ErrInvalidVault so callers
// cannot use the API as a password oracle.
func Decrypt(vaultText string, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}
	if vaultText == "" {
		return nil, ErrInvalidVault
	}
	vaultText = strings.ReplaceAll(vaultText, "\r\n", "\n")
	if strings.ContainsRune(vaultText, '\r') {
		return nil, ErrInvalidVault
	}
	vaultText = strings.TrimSuffix(vaultText, "\n")
	lines := strings.Split(vaultText, "\n")
	if len(lines) < 2 || !isSupportedHeader(lines[0]) {
		return nil, ErrInvalidVault
	}

	var body strings.Builder
	for _, line := range lines[1:] {
		if len(line) == 0 || len(line) > lineWidth || !isHex(line) {
			return nil, ErrInvalidVault
		}
		body.WriteString(line)
	}
	payload, err := hex.DecodeString(body.String())
	if err != nil {
		return nil, ErrInvalidVault
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
		return nil, ErrInvalidVault
	}

	salt, err := hex.DecodeString(fields[0])
	if err != nil || len(salt) != saltSize {
		return nil, ErrInvalidVault
	}
	expectedMAC, err := hex.DecodeString(fields[1])
	if err != nil || len(expectedMAC) != macSize {
		return nil, ErrInvalidVault
	}
	ciphertext, err := hex.DecodeString(fields[2])
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrInvalidVault
	}

	keyMaterial := derive(password, salt)
	key := keyMaterial[:keySize]
	macKey := keyMaterial[keySize : keySize+macSize]
	iv := keyMaterial[keySize+macSize : keySize+macSize+ivSize]
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(ciphertext)
	if !hmac.Equal(expectedMAC, mac.Sum(nil)) {
		return nil, ErrInvalidVault
	}

	plaintext := make([]byte, len(ciphertext))
	stream, err := newCTR(key, iv)
	if err != nil {
		return nil, ErrInvalidVault
	}
	stream.XORKeyStream(plaintext, ciphertext)
	plaintext, ok := pkcs7Unpad(plaintext, aes.BlockSize)
	if !ok {
		return nil, ErrInvalidVault
	}
	return plaintext, nil
}

// Reencrypt decrypts a Vault value with the source password and encrypts it
// with the destination password and label without returning the plaintext.
func Reencrypt(vaultText string, sourcePassword, destinationPassword []byte, destinationVaultID string) (string, error) {
	plaintext, err := Decrypt(vaultText, sourcePassword)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(plaintext) {
		return "", ErrInvalidVault
	}
	if len(plaintext) > MaxPlaintextBytes {
		return "", ErrPlaintextTooLarge
	}
	return Encrypt(plaintext, destinationPassword, destinationVaultID)
}

func isSupportedHeader(header string) bool {
	if header == Header11 {
		return true
	}
	parts := strings.Split(header, ";")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	if parts[0] != "$ANSIBLE_VAULT" || parts[1] != "1.2" || parts[2] != "AES256" {
		return false
	}
	return len(parts) == 3 || ValidateVaultID(parts[3]) == nil
}

func derive(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, pbkdf2Iterations, derivedKeySize, sha256.New)
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func pkcs7Pad(value []byte, blockSize int) []byte {
	padding := blockSize - len(value)%blockSize
	padded := make([]byte, len(value)+padding)
	copy(padded, value)
	for index := len(value); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(value []byte, blockSize int) ([]byte, bool) {
	if len(value) == 0 || len(value)%blockSize != 0 {
		return nil, false
	}
	padding := int(value[len(value)-1])
	if padding == 0 || padding > blockSize || padding > len(value) {
		return nil, false
	}
	for _, current := range value[len(value)-padding:] {
		if int(current) != padding {
			return nil, false
		}
	}
	return value[:len(value)-padding], true
}

func isHex(value string) bool {
	for _, current := range value {
		if !((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f') || (current >= 'A' && current <= 'F')) {
			return false
		}
	}
	return true
}
