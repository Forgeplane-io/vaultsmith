package attestation

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Match the existing HTTP/MCP encoded-component bound, not a decoded-byte cap.
const testEncodedComponentLimit = 64 << 10

var nestedJSONShapes = []struct {
	name, open, close string
}{
	{"object", `{"x":`, `}`},
	{"array", `[`, `]`},
}

func TestStrictJSONContainerDepth(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		valid     bool
	}{
		{"scalar", `"\ud834\udd1e"`, true},
		{"empty object", `{}`, true},
		{"empty array", `[]`, true},
		{"object object", `{"x":{}}`, true},
		{"object array", `{"x":[]}`, true},
		{"array object", `[{}]`, true},
		{"array array", `[[]]`, true},
		{"siblings and scalars", `{"input":{"x":1},"output":{"x":true},"binding":{"x":null},"s":"[]{}"}`, true},
		{"nested Unicode", `{"x":{"s":"\ud834\udd1e"}}`, true},
		{"escaped duplicate", `{"x":{"s":1,"\u0073":2}}`, false},
		{"nested lone surrogate", `{"x":{"s":"\ud800"}}`, false},
		{"object object object", `{"x":{"x":{}}}`, false},
		{"object object array", `{"x":{"x":[]}}`, false},
		{"object array object", `{"x":[{}]}`, false},
		{"object array array", `{"x":[[]]}`, false},
		{"array object object", `[{"x":{}}]`, false},
		{"array object array", `[{"x":[]}]`, false},
		{"array array object", `[[{}]]`, false},
		{"array array array", `[[[]]]`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseStrictJSON([]byte(test.raw))
			if test.valid && err != nil {
				t.Fatalf("legal depth error = %v", err)
			}
			if !test.valid && !errors.Is(err, errStrictJSON) {
				t.Fatalf("invalid structure error = %v, want strict JSON error", err)
			}
		})
	}
}

func TestStrictJSONRejectsDeepValuesEarly(t *testing.T) {
	for _, shape := range nestedJSONShapes {
		for _, levels := range []int{2, maxNestedJSONLevels(shape.open, shape.close)} {
			t.Run(fmt.Sprintf("%s/depth%d", shape.name, levels+1), func(t *testing.T) {
				raw := nestedJSONFixture(shape.open, shape.close, levels)
				parser := strictJSONParser{data: raw}
				_, err := parser.parseValue()
				if !errors.Is(err, errStrictJSON) {
					t.Fatalf("unsupported nesting error = %v, want strict JSON error", err)
				}
				// The third container must not be entered or constructed, even
				// when thousands of syntactically valid containers follow it.
				if want := len(`{"x":`) + len(shape.open); parser.pos != want {
					t.Fatalf("parser consumed %d bytes, want rejection at byte %d", parser.pos, want)
				}
			})
		}
	}
}

func TestVerifyNestedJSONBeforeResolution(t *testing.T) {
	valid, err := Sign(testClaims(t), testKid, testPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{"protected", "payload", "outer"} {
		for _, shape := range nestedJSONShapes {
			for _, levels := range []int{0, maxNestedJSONLevels(shape.open, shape.close)} {
				t.Run(fmt.Sprintf("%s/%s/depth%d", component, shape.name, levels+1), func(t *testing.T) {
					raw := nestedJSONFixture(shape.open, shape.close, levels)
					encoded := encodeBase64URL(raw)
					if len(encoded) > testEncodedComponentLimit {
						t.Fatalf("encoded-component budget=%d observed=%d; resize synthetic fixture", testEncodedComponentLimit, len(encoded))
					}
					calls := 0
					options := VerifyOptions{
						ExpectedIssuer: testIssuer,
						Resolver: resolverFunc(func(string, string) (KeyResolution, error) {
							calls++
							return KeyResolution{}, errors.New("unexpected resolution")
						}),
					}
					candidate := valid
					switch component {
					case "protected":
						candidate.Protected = encoded
					case "payload":
						candidate.Payload = encoded
					}
					wire := raw
					if component != "outer" {
						claims, err := Verify(candidate, options)
						if err != ErrMalformed || claims != (RotationClaims{}) {
							t.Fatalf("Verify: safe malformed=%v zero claims=%v", err == ErrMalformed, claims == (RotationClaims{}))
						}
						wire = mustMarshal(t, candidate)
					} else if signed, err := Parse(raw); err != ErrMalformed || signed != (Signed{}) {
						t.Fatalf("Parse: safe malformed=%v zero JWS=%v", err == ErrMalformed, signed == (Signed{}))
					}
					claims, err := VerifyJSON(wire, options)
					if err != ErrMalformed || claims != (RotationClaims{}) || calls != 0 {
						t.Fatalf("VerifyJSON: safe malformed=%v zero claims=%v resolver calls=%d", err == ErrMalformed, claims == (RotationClaims{}), calls)
					}
				})
			}
		}
	}
}

func maxNestedJSONLevels(open, close string) int {
	return (testEncodedComponentLimit*3/4 - len(`{"x":0}`)) / (len(open) + len(close))
}

func nestedJSONFixture(open, close string, levels int) []byte {
	return []byte(`{"x":` + strings.Repeat(open, levels) + `0` + strings.Repeat(close, levels) + `}`)
}
