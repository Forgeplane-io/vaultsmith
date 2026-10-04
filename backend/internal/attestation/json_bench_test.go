package attestation

import (
	"runtime"
	"testing"
)

func BenchmarkVerifyNestedJSON(b *testing.B) {
	valid, err := Sign(testClaimsForFuzz(), testKid, testPrivateKey())
	if err != nil {
		b.Fatal(err)
	}
	for _, component := range []string{"protected", "payload"} {
		for _, shape := range nestedJSONShapes {
			for _, workload := range []string{"shallow", "deep"} {
				b.Run(component+"/"+shape.name+"/"+workload, func(b *testing.B) {
					options := VerifyOptions{
						ExpectedIssuer: testIssuer,
						Resolver: resolverFunc(func(string, string) (KeyResolution, error) {
							b.Fatal("malformed input reached resolver")
							return KeyResolution{}, nil
						}),
					}
					levels := 1
					if workload == "deep" {
						levels = maxNestedJSONLevels(shape.open, shape.close)
					}
					encoded := encodeBase64URL(nestedJSONFixture(shape.open, shape.close, levels))
					if len(encoded) > testEncodedComponentLimit {
						b.Fatalf("encoded-component budget=%d observed=%d; resize synthetic fixture", testEncodedComponentLimit, len(encoded))
					}
					candidate := valid
					if component == "protected" {
						candidate.Protected = encoded
					} else {
						candidate.Payload = encoded
					}
					// Fixture construction, one warm-up and GC are outside b.Loop.
					if _, err := Verify(candidate, options); err != ErrMalformed {
						b.Fatal("warm-up did not return safe malformed error")
					}
					runtime.GC()
					b.ReportAllocs()
					for b.Loop() {
						claims, err := Verify(candidate, options)
						if err != ErrMalformed || claims != (RotationClaims{}) {
							b.Fatal("verification outcome changed")
						}
					}
					b.ReportMetric(float64(len(encoded)), "component-bytes")
					b.ReportMetric(float64(levels+1), "container-depth")
				})
			}
		}
	}
}
