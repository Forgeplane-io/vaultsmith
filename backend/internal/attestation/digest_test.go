package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
)

func TestDigestBytesMatchConcatenationWithoutMutatingInput(t *testing.T) {
	for _, role := range []struct {
		name   string
		domain string
		digest func([]byte) string
	}{
		{"input", "vaultsmith:rotation-attestation:input:v1\x00", InputDigestBytes},
		{"output", "vaultsmith:rotation-attestation:output:v1\x00", OutputDigestBytes},
	} {
		t.Run(role.name, func(t *testing.T) {
			empty := sha256.Sum256([]byte(role.domain))
			if role.digest(nil) != hex.EncodeToString(empty[:]) {
				t.Fatal("nil input changed the domain digest")
			}
			// Cover the combined message's padding/block boundaries and caller
			// buffers around a SHA-256 block, plus the existing Vault byte limit.
			for _, size := range []int{
				0, 1,
				sha256.BlockSize - 9 - len(role.domain),
				sha256.BlockSize - 8 - len(role.domain),
				sha256.BlockSize - 1 - len(role.domain),
				sha256.BlockSize - len(role.domain),
				sha256.BlockSize + 1 - len(role.domain),
				sha256.BlockSize - 1, sha256.BlockSize, sha256.BlockSize + 1,
				ansiblevault.MaxVaultTextBytes,
			} {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					storage := bytes.Repeat([]byte{0x5a}, size+sha256.BlockSize)
					before := bytes.Clone(storage)
					canonical := storage[:size]
					want := sha256.Sum256(append([]byte(role.domain), canonical...))
					if role.digest(canonical) != hex.EncodeToString(want[:]) {
						t.Fatal("digest differs from the independent concatenation oracle")
					}
					if !bytes.Equal(storage, before) {
						t.Fatal("digest modified the input or its spare capacity")
					}
				})
			}
		})
	}
}
