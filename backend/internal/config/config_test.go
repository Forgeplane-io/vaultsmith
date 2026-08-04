package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
)

func TestLoadJSONPreservesPublicOrdering(t *testing.T) {
	lookup := map[string]string{
		"VAULT_PASSWORD_FIRST":  "first-secret",
		"VAULT_PASSWORD_SECOND": "second-secret",
	}
	loaded, err := LoadJSON(`[
		{"id":"first","label":"First","passwordEnv":"VAULT_PASSWORD_FIRST"},
		{"id":"second","label":"Second","passwordEnv":"VAULT_PASSWORD_SECOND"}
	]`, mapLookup(lookup))
	if err != nil {
		t.Fatalf("LoadJSON() error = %v", err)
	}
	want := []PublicProfile{{ID: "first", Label: "First"}, {ID: "second", Label: "Second"}}
	if got := loaded.PublicProfiles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PublicProfiles() = %#v, want %#v", got, want)
	}

	encoded, err := loaded.Executor().Execute("first", "encrypt", "fixture-value")
	if err != nil {
		t.Fatalf("Executor().Execute(encrypt) error = %v", err)
	}
	if !strings.HasPrefix(encoded, ansiblevault.Header12Prefix+";first\n") {
		t.Fatalf("encoded header = %q, want Vault 1.2 label", strings.SplitN(encoded, "\n", 2)[0])
	}
	decoded, err := loaded.Executor().Execute("first", "decrypt", encoded)
	if err != nil {
		t.Fatalf("Executor().Execute(decrypt) error = %v", err)
	}
	if decoded != "fixture-value" {
		t.Fatalf("decoded value = %q, want %q", decoded, "fixture-value")
	}
}

func TestExecutorRotateUsesDestinationProfile(t *testing.T) {
	loaded, err := LoadJSON(`[
		{"id":"source","label":"Source","passwordEnv":"VAULT_PASSWORD_SOURCE"},
		{"id":"destination","label":"Destination","passwordEnv":"VAULT_PASSWORD_DESTINATION"}
	]`, mapLookup(map[string]string{
		"VAULT_PASSWORD_SOURCE":      "source-password",
		"VAULT_PASSWORD_DESTINATION": "destination-password",
	}))
	if err != nil {
		t.Fatalf("LoadJSON() error = %v", err)
	}
	input, err := loaded.Executor().Execute("source", "encrypt", "fixture-value")
	if err != nil {
		t.Fatalf("encrypt source value: %v", err)
	}
	rotated, err := loaded.Executor().Rotate("source", "destination", input)
	if err != nil {
		t.Fatalf("rotate value: %v", err)
	}
	if !strings.HasPrefix(rotated, ansiblevault.Header12Prefix+";destination\n") {
		t.Fatalf("rotated header = %q, want destination label", strings.SplitN(rotated, "\n", 2)[0])
	}
	decoded, err := loaded.Executor().Execute("destination", "decrypt", rotated)
	if err != nil {
		t.Fatalf("decrypt rotated value: %v", err)
	}
	if decoded != "fixture-value" {
		t.Fatalf("rotated plaintext = %q, want fixture-value", decoded)
	}
	for _, profileID := range []string{"missing", "destination"} {
		sourceID := profileID
		if profileID == "destination" {
			sourceID = "source"
		}
		if _, err := loaded.Executor().Rotate(sourceID, "missing", input); !errors.Is(err, ErrProfileNotFound) {
			t.Fatalf("Rotate(%q, missing) error = %v, want ErrProfileNotFound", sourceID, err)
		}
	}
	if _, err := loaded.Executor().Rotate("missing", "destination", input); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Rotate(missing, destination) error = %v, want ErrProfileNotFound", err)
	}
}

func TestLoadJSONRejectsInvalidConfiguration(t *testing.T) {
	const secret = "do-not-leak-this-secret"
	cases := []struct {
		name string
		json string
		env  map[string]string
	}{
		{name: "empty document", json: "", env: nil},
		{name: "malformed json", json: "[", env: nil},
		{name: "object instead of array", json: `{ "profiles": [] }`, env: nil},
		{name: "empty profiles", json: `[]`, env: nil},
		{name: "unknown field", json: `[{"id":"dev","label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV","password":"` + secret + `"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": secret}},
		{name: "missing id", json: `[{"label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": secret}},
		{name: "invalid id", json: `[{"id":"Dev!","label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": secret}},
		{name: "empty label", json: `[{"id":"dev","label":"  ","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": secret}},
		{name: "invalid password env", json: `[{"id":"dev","label":"Dev","passwordEnv":"not-valid"}]`, env: map[string]string{"not-valid": secret}},
		{name: "duplicate ids", json: `[{"id":"dev","label":"One","passwordEnv":"VAULT_PASSWORD_ONE"},{"id":"dev","label":"Two","passwordEnv":"VAULT_PASSWORD_TWO"}]`, env: map[string]string{"VAULT_PASSWORD_ONE": secret, "VAULT_PASSWORD_TWO": secret}},
		{name: "duplicate password env", json: `[{"id":"one","label":"One","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"two","label":"Two","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": secret}},
		{name: "reserved profiles env", json: `[{"id":"dev","label":"Dev","passwordEnv":"VAULT_PROFILES_JSON"}]`, env: map[string]string{"VAULT_PROFILES_JSON": secret}},
		{name: "reserved http env", json: `[{"id":"dev","label":"Dev","passwordEnv":"HTTP_ADDR"}]`, env: map[string]string{"HTTP_ADDR": secret}},
		{name: "missing password env", json: `[{"id":"dev","label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: nil},
		{name: "empty password env", json: `[{"id":"dev","label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV"}]`, env: map[string]string{"VAULT_PASSWORD_DEV": ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadJSON(tc.json, mapLookup(tc.env))
			if err == nil {
				t.Fatal("LoadJSON() unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked password: %v", err)
			}
		})
	}
}

func TestExecutorErrorsAreClassifiable(t *testing.T) {
	loaded, err := LoadJSON(`[{"id":"dev","label":"Dev","passwordEnv":"VAULT_PASSWORD_DEV"}]`, mapLookup(map[string]string{"VAULT_PASSWORD_DEV": "password"}))
	if err != nil {
		t.Fatalf("LoadJSON() error = %v", err)
	}
	if _, err := loaded.Executor().Execute("missing", "encrypt", "value"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("unknown profile error = %v, want ErrProfileNotFound", err)
	}
	if _, err := loaded.Executor().Execute("dev", "rotate", "value"); !errors.Is(err, ErrUnsupportedMode) {
		t.Fatalf("unknown mode error = %v, want ErrUnsupportedMode", err)
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
