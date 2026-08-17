package generate

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestGenerateTokenUsesCanonicalEncodingsAndEffectiveParameters(t *testing.T) {
	raw := make([]byte, 64)
	for index := range raw {
		raw[index] = byte(index)
	}
	hexEncoding := TokenEncodingHex
	sixteenBytes := 16

	tests := []struct {
		name       string
		parameters TokenParameters
		raw        []byte
		want       string
		format     string
		effective  EffectiveTokenParameters
	}{
		{
			name:       "default base64url",
			parameters: TokenParameters{},
			raw:        raw[:32],
			want:       base64.RawURLEncoding.EncodeToString(raw[:32]),
			format:     TokenBase64Format,
			effective:  EffectiveTokenParameters{Encoding: TokenEncodingBase64URL, Bytes: 32},
		},
		{
			name:       "lowercase hex",
			parameters: TokenParameters{Encoding: &hexEncoding, Bytes: &sixteenBytes},
			raw:        raw[:16],
			want:       hex.EncodeToString(raw[:16]),
			format:     TokenHexFormat,
			effective:  EffectiveTokenParameters{Encoding: TokenEncodingHex, Bytes: 16},
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			generator := New()
			generator.random = bytes.NewReader(current.raw)
			result, err := generator.GenerateToken(current.parameters)
			if err != nil {
				t.Fatalf("GenerateToken() error = %v", err)
			}
			if got := string(result.PrivateBytes()); got != current.want {
				t.Fatalf("token = %q, want %q", got, current.want)
			}
			if result.Format() != current.format {
				t.Fatalf("format = %q, want %q", result.Format(), current.format)
			}
			if got := result.EffectiveParameters(); !reflect.DeepEqual(got, current.effective) {
				t.Fatalf("effective parameters = %#v, want %#v", got, current.effective)
			}
		})
	}
}

func TestGenerateTokenRejectsInvalidParametersBeforeRandomness(t *testing.T) {
	zeroBytes := 0
	fifteenBytes := 15
	sixtyFiveBytes := 65
	emptyEncoding := TokenEncoding("")
	unsupportedEncoding := TokenEncoding("base64")
	tests := []TokenParameters{
		{Bytes: &zeroBytes},
		{Bytes: &fifteenBytes},
		{Bytes: &sixtyFiveBytes},
		{Encoding: &emptyEncoding},
		{Encoding: &unsupportedEncoding},
	}
	for _, parameters := range tests {
		reader := &countingTokenReader{}
		generator := New()
		generator.random = reader
		if _, err := generator.GenerateToken(parameters); !errors.Is(err, ErrInvalidParameters) {
			t.Fatalf("GenerateToken(%#v) error = %v, want ErrInvalidParameters", parameters, err)
		}
		if reader.reads != 0 {
			t.Fatalf("GenerateToken(%#v) consumed randomness %d times", parameters, reader.reads)
		}
	}
}

func TestGenerateTokenRandomFailureReturnsNoMaterial(t *testing.T) {
	generator := New()
	generator.random = &shortTokenReader{remaining: 8}
	result, err := generator.GenerateToken(TokenParameters{})
	if !errors.Is(err, ErrGenerationFailed) {
		t.Fatalf("GenerateToken() error = %v, want ErrGenerationFailed", err)
	}
	if private := result.PrivateBytes(); len(private) != 0 {
		t.Fatalf("failed result contains %d private bytes", len(private))
	}
}

type countingTokenReader struct {
	reads int
}

func (r *countingTokenReader) Read(buffer []byte) (int, error) {
	r.reads++
	clear(buffer)
	return len(buffer), nil
}

type shortTokenReader struct {
	remaining int
}

func (r *shortTokenReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if count > r.remaining {
		count = r.remaining
	}
	clear(buffer[:count])
	r.remaining -= count
	return count, nil
}
