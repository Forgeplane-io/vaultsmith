package attestationkeyring

import "testing"

func FuzzParseNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":1,"active":"rotation-2026-08","keys":[]}`))
	f.Add([]byte(`{"version":1,"active":"rotation-2026-08","keys":[{"id":"rotation-2026-08","state":"active"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data, testIssuer)
	})
}
