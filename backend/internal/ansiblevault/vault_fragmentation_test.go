package ansiblevault

import (
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

// Failure modes: delimiter-sized allocations in header/outer/inner parsing; accepting
// extra/empty fields; rejecting valid one-nibble wrapping; changed canonical
// bytes or password-error precedence. Fixtures contain only synthetic data.
func fragmentedEnvelopeWorkloads(t testing.TB) map[string]string {
	t.Helper()
	const header = Header11 + "\n"
	outer := header + strings.Repeat("0\n", (MaxVaultTextBytes-len(header))/2)
	// Each decoded newline is two outer hex characters; account for wrapping.
	bodyLength := (MaxVaultTextBytes - len(header)) * lineWidth / (lineWidth + 1)
	bodyLength -= bodyLength % 2
	inner := formatEnvelope(Header11, strings.Repeat("0a", bodyLength/2), lineWidth, "\n", true)
	const headerPrefix = Header12Prefix + ";"
	const headerSuffix = "\n00\n"
	return map[string]string{
		"header": headerPrefix + strings.Repeat(";", MaxVaultTextBytes-len(headerPrefix)-len(headerSuffix)) + headerSuffix,
		"outer":  outer,
		"inner":  inner,
		"valid":  boundaryEnvelope(t, MaxVaultTextBytes),
	}
}

func TestEnvelopeFragmentation(t *testing.T) {
	for name, input := range fragmentedEnvelopeWorkloads(t) {
		if len(input) > MaxVaultTextBytes {
			t.Fatalf("fixture exceeds existing value budget: configured=%d observed=%d; reduce fixture", MaxVaultTextBytes, len(input))
		}
		if name == "valid" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if output, err := CanonicalEnvelope(input); err != ErrInvalidVault || output != nil {
				t.Fatalf("canonical rejection: error=%v output_bytes=%d", err, len(output))
			}
			if output, err := Decrypt(input, []byte("synthetic-password")); err != ErrInvalidVault || output != nil {
				t.Fatalf("decrypt rejection: error=%v output_bytes=%d", err, len(output))
			}
			if _, err := Decrypt(input, nil); err != ErrInvalidPassword {
				t.Fatalf("empty-password precedence: %v", err)
			}
		})
	}
}

func TestEnvelopeHeaderAllocation(t *testing.T) {
	input := fragmentedEnvelopeWorkloads(t)["header"]
	password := []byte("synthetic-password")
	for _, operation := range []struct {
		name string
		run  func(string) ([]byte, error)
	}{
		{"canonical", CanonicalEnvelope},
		{"decrypt", func(input string) ([]byte, error) { return Decrypt(input, password) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			// Exclude fixture construction. The existing value ceiling is a coarse
			// tripwire against delimiter-cardinality rejection allocation, not a new
			// header-length policy. Re-measure if runtime overhead changes this gate.
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			output, err := operation.run(input)
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(input)
			if err != ErrInvalidVault || output != nil {
				t.Fatalf("header rejection: invalid_vault=%t output_bytes=%d", err == ErrInvalidVault, len(output))
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			if allocated > uint64(MaxVaultTextBytes) {
				t.Fatalf("malformed-header rejection allocation budget: configured=%d observed=%d input_bytes=%d; inspect delimiter-cardinality allocations", MaxVaultTextBytes, allocated, len(input))
			}
			t.Logf("input_bytes=%d rejection_allocated_bytes=%d allocation_budget=%d", len(input), allocated, MaxVaultTextBytes)
		})
	}
}

func TestEnvelopeNarrowWrappingAndInnerFields(t *testing.T) {
	inner := strings.Repeat("ab", 32) + "\n" + strings.Repeat("cd", 32) + "\n" + strings.Repeat("ef", 16)
	for _, header := range []string{Header11, Header12Prefix, Header12Prefix + ";synthetic"} {
		input := formatEnvelope(header, strings.ToUpper(hex.EncodeToString([]byte(inner))), 1, "\r\n", false)
		output, err := CanonicalEnvelope(input)
		if err != nil || string(output) != formatEnvelope(header, hex.EncodeToString([]byte(inner)), lineWidth, "\n", true) {
			t.Fatalf("one-nibble canonicalization: error=%v", err)
		}
	}
	for _, malformed := range []string{inner + "\n", inner + "\n00", strings.Replace(inner, "\n", "", 1), "\n" + inner, strings.Replace(inner, "\n", "\n\n", 1)} {
		input := formatEnvelope(Header11, hex.EncodeToString([]byte(malformed)), lineWidth, "\n", true)
		if _, err := CanonicalEnvelope(input); err != ErrInvalidVault {
			t.Fatalf("inner field rejection: %v", err)
		}
	}
}

func BenchmarkEnvelopeFragmentation(b *testing.B) {
	// Setup excluded; all workloads stay within the existing five-MiB ceiling.
	workloads := fragmentedEnvelopeWorkloads(b)
	for _, name := range []string{"valid", "header", "outer", "inner"} {
		input := workloads[name]
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				_, err := CanonicalEnvelope(input)
				if (name == "valid" && err != nil) || (name != "valid" && err != ErrInvalidVault) {
					b.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
