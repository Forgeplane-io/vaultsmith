package ansiblevault

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCanonicalEnvelopeNormalizesSupportedFormats(t *testing.T) {
	inner := strings.Repeat("ab", 32) + "\n" + strings.Repeat("cd", 32) + "\n" + strings.Repeat("ef", 16)
	body := strings.ToUpper(hex.EncodeToString([]byte(inner)))
	for _, test := range []struct {
		name    string
		header  string
		newline string
		finalLF bool
	}{
		{name: "vault 1.1 LF", header: Header11, newline: "\n", finalLF: true},
		{name: "vault 1.1 CRLF no final", header: Header11, newline: "\r\n"},
		{name: "vault 1.2 labeled", header: Header12Prefix + ";dev", newline: "\n", finalLF: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := formatEnvelope(test.header, body, 37, test.newline, test.finalLF)
			canonical, err := CanonicalEnvelope(input)
			if err != nil {
				t.Fatalf("CanonicalEnvelope() error = %v", err)
			}
			expected := formatEnvelope(test.header, strings.ToLower(body), lineWidth, "\n", true)
			if string(canonical) != expected {
				t.Fatalf("canonical output mismatch\n got: %q\nwant: %q", canonical, expected)
			}
			if _, err := Decrypt(input, []byte("not-the-password")); err != ErrInvalidVault {
				t.Fatalf("refactored parser error = %v, want ErrInvalidVault", err)
			}
		})
	}
}

func TestCanonicalEnvelopeRejectsMalformedInput(t *testing.T) {
	validBody := strings.Repeat("00", 32) + "\n" + strings.Repeat("11", 32) + "\n" + strings.Repeat("22", 16)
	validOuter := hex.EncodeToString([]byte(validBody))
	valid := formatEnvelope(Header11, validOuter, lineWidth, "\n", true)
	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "extra trailing blank", input: valid + "\n"},
		{name: "lone CR", input: strings.Replace(valid, "\n", "\r", 1)},
		{name: "invalid UTF-8", input: string(append([]byte(valid), 0xff))},
		{name: "invalid header", input: "$ANSIBLE_VAULT;1.3;AES256\n" + validOuter},
		{name: "invalid body", input: Header11 + "\nnot-hex"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CanonicalEnvelope(test.input); err != ErrInvalidVault {
				t.Fatalf("CanonicalEnvelope() error = %v, want ErrInvalidVault", err)
			}
		})
	}
}

func TestCanonicalEnvelopeSizeBoundary(t *testing.T) {
	exact := boundaryEnvelope(t, MaxVaultTextBytes)
	canonical, err := CanonicalEnvelope(exact)
	if err != nil {
		t.Fatalf("exact boundary error = %v", err)
	}
	if len(exact) != MaxVaultTextBytes {
		t.Fatalf("exact input length = %d, want %d", len(exact), MaxVaultTextBytes)
	}
	if len(canonical) != MaxVaultTextBytes {
		t.Fatalf("canonical exact length = %d, want %d", len(canonical), MaxVaultTextBytes)
	}

	over := boundaryEnvelope(t, MaxVaultTextBytes+1)
	if len(over) != MaxVaultTextBytes+1 {
		t.Fatalf("oversize input length = %d, want %d", len(over), MaxVaultTextBytes+1)
	}
	if _, err := CanonicalEnvelope(over); err != ErrInvalidVault {
		t.Fatalf("oversize error = %v, want ErrInvalidVault", err)
	}
}

func formatEnvelope(header, body string, width int, newline string, finalLF bool) string {
	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteString(newline)
	for len(body) > width {
		builder.WriteString(body[:width])
		builder.WriteString(newline)
		body = body[width:]
	}
	builder.WriteString(body)
	if finalLF {
		builder.WriteString(newline)
	}
	return builder.String()
}

func boundaryEnvelope(t *testing.T, target int) string {
	t.Helper()
	for labelLength := 1; labelLength <= 128; labelLength++ {
		header := Header12Prefix + ";" + strings.Repeat("x", labelLength)
		for _, finalLF := range []bool{false, true} {
			start := target - len(header) - target/80 + 800
			for bodyLength := start; bodyLength < start+300; bodyLength++ {
				internalNewlines := (bodyLength - 1) / lineWidth
				actualLength := len(header) + 1 + bodyLength + internalNewlines
				if finalLF {
					actualLength++
				}
				if bodyLength <= 0 || actualLength != target || bodyLength%2 != 0 || bodyLength%64 != 4 {
					continue
				}
				decodedLength := bodyLength / 2
				const fixedFields = 64 + 1 + 64 + 1
				cipherHexLength := decodedLength - fixedFields
				if cipherHexLength < 32 || cipherHexLength%32 != 0 {
					continue
				}
				inner := strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64) + "\n" + strings.Repeat("c", cipherHexLength)
				body := hex.EncodeToString([]byte(inner))
				if len(body) != bodyLength {
					continue
				}
				return formatEnvelope(header, body, lineWidth, "\n", finalLF)
			}
		}
	}
	t.Fatalf("could not construct valid envelope of %d bytes", target)
	return ""
}
