package generate

import (
	"encoding/base64"
	"encoding/hex"
	"io"
)

const (
	defaultTokenBytes = 32
	minimumTokenBytes = 16
	maximumTokenBytes = 64
)

// GenerateToken creates a token from the requested number of independent random
// bytes, then applies the canonical unpadded base64url or lowercase hex
// encoding.
func (g *Generator) GenerateToken(parameters TokenParameters) (TokenResult, error) {
	effective, format, err := resolveTokenParameters(parameters)
	if err != nil {
		return TokenResult{}, err
	}
	if g == nil || g.random == nil {
		return TokenResult{}, ErrGenerationFailed
	}

	raw := make([]byte, effective.Bytes)
	if _, err := io.ReadFull(g.random, raw); err != nil {
		clear(raw)
		return TokenResult{}, ErrGenerationFailed
	}

	var encoded []byte
	switch effective.Encoding {
	case TokenEncodingBase64URL:
		encoded = make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
		base64.RawURLEncoding.Encode(encoded, raw)
	case TokenEncodingHex:
		encoded = make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(encoded, raw)
	default:
		clear(raw)
		return TokenResult{}, ErrInvalidParameters
	}
	clear(raw)

	private := newPrivateMaterial(encoded)
	clear(encoded)
	return TokenResult{private: private, parameters: effective, format: format}, nil
}

func resolveTokenParameters(parameters TokenParameters) (EffectiveTokenParameters, string, error) {
	effective := EffectiveTokenParameters{
		Encoding: TokenEncodingBase64URL,
		Bytes:    defaultTokenBytes,
	}
	if parameters.Encoding != nil {
		effective.Encoding = *parameters.Encoding
	}
	if parameters.Bytes != nil {
		effective.Bytes = *parameters.Bytes
	}
	if effective.Bytes < minimumTokenBytes || effective.Bytes > maximumTokenBytes {
		return EffectiveTokenParameters{}, "", ErrInvalidParameters
	}
	switch effective.Encoding {
	case TokenEncodingBase64URL:
		return effective, TokenBase64Format, nil
	case TokenEncodingHex:
		return effective, TokenHexFormat, nil
	default:
		return EffectiveTokenParameters{}, "", ErrInvalidParameters
	}
}
