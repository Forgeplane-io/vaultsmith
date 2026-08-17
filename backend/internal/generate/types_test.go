package generate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGeneratorResultsRejectGenericSerializationAndFormattingLeaks(t *testing.T) {
	const privateMarker = "synthetic-private-material"
	const publicMarker = "synthetic-public-material"
	results := []any{
		PasswordResult{private: newPrivateMaterial([]byte(privateMarker))},
		TokenResult{private: newPrivateMaterial([]byte(privateMarker))},
		SSHKeyPairResult{
			private:       newPrivateMaterial([]byte(privateMarker)),
			authorizedKey: publicMarker,
			fingerprint:   publicMarker,
		},
		AgeIdentityResult{
			private:   newPrivateMaterial([]byte(privateMarker)),
			recipient: publicMarker,
		},
		X509CSRResult{
			private:     newPrivateMaterial([]byte(privateMarker)),
			csrPEM:      publicMarker,
			fingerprint: publicMarker,
		},
	}

	for _, result := range results {
		t.Run(fmt.Sprintf("%T", result), func(t *testing.T) {
			encoded, err := json.Marshal(result)
			if !errors.Is(err, ErrResultSerialization) || encoded != nil {
				t.Fatalf("json.Marshal() = %q, %v; want nil and ErrResultSerialization", encoded, err)
			}
			for _, rendered := range []string{
				fmt.Sprint(result),
				fmt.Sprintf("%+v", result),
				fmt.Sprintf("%#v", result),
				err.Error(),
			} {
				if strings.Contains(rendered, privateMarker) || strings.Contains(rendered, publicMarker) {
					t.Fatalf("generic rendering leaked result material: %q", rendered)
				}
			}
		})
	}
}

func TestPrivateMaterialDoesNotAliasInputsOrOutputs(t *testing.T) {
	input := []byte("original-private-material")
	material := newPrivateMaterial(input)
	clear(input)

	first := material.clone()
	if string(first) != "original-private-material" {
		t.Fatalf("stored private material changed with caller input: %q", first)
	}
	clear(first)
	second := material.clone()
	if string(second) != "original-private-material" {
		t.Fatalf("stored private material changed with caller output: %q", second)
	}
}
