package attestation

import (
	"bytes"
	"strconv"
	"testing"
)

// BenchmarkDigestBytes measures the domain-separated SHA-256 cost after a
// caller has already canonicalized a synthetic Vault envelope. It intentionally
// uses bytes rather than a real secret or ciphertext.
func BenchmarkDigestBytes(b *testing.B) {
	for _, size := range []int{1024, 64 * 1024, 1024 * 1024, 5 * 1024 * 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			canonical := bytes.Repeat([]byte("a"), size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = InputDigestBytes(canonical)
				_ = OutputDigestBytes(canonical)
			}
		})
	}
}
