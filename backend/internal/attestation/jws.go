package attestation

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gowebpki/jcs"
)

var signedMembers = map[string]struct{}{
	"protected": {}, "payload": {}, "signature": {},
}

// Signed is the flattened JWS JSON serialization used by rotation
// attestations. Its JSON representation contains no unprotected members.
type Signed struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// MarshalJSON emits the outer flattened object with JCS member ordering.
// Verification intentionally accepts any outer-member order through Parse.
func (s Signed) MarshalJSON() ([]byte, error) {
	type wire Signed
	raw, err := json.Marshal(wire(s))
	if err != nil {
		return nil, ErrMalformed
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	return canonical, nil
}

// Marshal returns the deterministic flattened JWS JSON bytes.
func Marshal(s Signed) ([]byte, error) {
	return s.MarshalJSON()
}

// Encode is an explicit alias for Marshal for callers that prefer protocol
// terminology.
func Encode(s Signed) ([]byte, error) {
	return Marshal(s)
}

// Parse parses a flattened JWS JSON object with strict duplicate-key and
// UTF-8 handling. Protected-header and payload JCS checks occur in Verify.
func Parse(data []byte) (Signed, error) {
	root, err := parseStrictJSON(data)
	if err != nil || root.kind != jsonObject || !root.hasOnlyMembers(signedMembers) {
		return Signed{}, ErrMalformed
	}
	protected, err := requiredStringMember(root, "protected")
	if err != nil {
		return Signed{}, ErrMalformed
	}
	payload, err := requiredStringMember(root, "payload")
	if err != nil {
		return Signed{}, ErrMalformed
	}
	signature, err := requiredStringMember(root, "signature")
	if err != nil {
		return Signed{}, ErrMalformed
	}
	result := Signed{Protected: protected, Payload: payload, Signature: signature}
	if _, _, _, err := decodeEncodedComponents(result); err != nil {
		return Signed{}, ErrMalformed
	}
	return result, nil
}

// Decode is an explicit alias for Parse.
func Decode(data []byte) (Signed, error) {
	return Parse(data)
}

func decodeEncodedComponents(s Signed) (protected, payload, signature []byte, err error) {
	protected, err = decodeStrictBase64URL(s.Protected)
	if err != nil || len(protected) == 0 {
		return nil, nil, nil, errMalformed
	}
	payload, err = decodeStrictBase64URL(s.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, nil, errMalformed
	}
	signature, err = decodeStrictBase64URL(s.Signature)
	if err != nil || len(signature) != 64 {
		return nil, nil, nil, errMalformed
	}
	return protected, payload, signature, nil
}

func decodeStrictBase64URL(value string) ([]byte, error) {
	if value == "" || strings.ContainsRune(value, '=') {
		return nil, errMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errMalformed
	}
	return decoded, nil
}

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
