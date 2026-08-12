package config

import (
	"context"
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

	encoded, err := executorForProfile(t, loaded.Executor(), "first").Encrypt(context.Background(), "fixture-value")
	if err != nil {
		t.Fatalf("Executor().Encrypt() error = %v", err)
	}
	if !strings.HasPrefix(encoded, ansiblevault.Header12Prefix+";first\n") {
		t.Fatalf("encoded header = %q, want Vault 1.2 label", strings.SplitN(encoded, "\n", 2)[0])
	}
	decoded, err := executorForProfile(t, loaded.Executor(), "first").Decrypt(context.Background(), encoded)
	if err != nil {
		t.Fatalf("Executor().Decrypt() error = %v", err)
	}
	if decoded != "fixture-value" {
		t.Fatalf("decoded value = %q, want %q", decoded, "fixture-value")
	}
}

func TestExecutorUsesSelectedProfileAndHonorsCancellation(t *testing.T) {
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
	input, err := executorForProfile(t, loaded.Executor(), "source").Encrypt(context.Background(), "fixture-value")
	if err != nil {
		t.Fatalf("encrypt source value: %v", err)
	}
	plaintext, err := executorForProfile(t, loaded.Executor(), "source").Decrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("decrypt source value: %v", err)
	}
	rotated, err := executorForProfile(t, loaded.Executor(), "destination").Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("encrypt destination value: %v", err)
	}
	if !strings.HasPrefix(rotated, ansiblevault.Header12Prefix+";destination\n") {
		t.Fatalf("destination header = %q, want destination label", strings.SplitN(rotated, "\n", 2)[0])
	}
	decoded, err := executorForProfile(t, loaded.Executor(), "destination").Decrypt(context.Background(), rotated)
	if err != nil {
		t.Fatalf("decrypt rotated value: %v", err)
	}
	if decoded != "fixture-value" {
		t.Fatalf("rotated plaintext = %q, want fixture-value", decoded)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, err := executorForProfile(t, loaded.Executor(), "source").Encrypt(ctx, "value"); !errors.Is(err, context.Canceled) || output != "" {
		t.Fatalf("Encrypt(canceled) = %q, %v, want empty/context.Canceled", output, err)
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
		{name: "reserved mcp enabled env", json: `[{"id":"dev","label":"Dev","passwordEnv":"MCP_ENABLED"}]`, env: map[string]string{"MCP_ENABLED": secret}},
		{name: "reserved mcp debug env", json: `[{"id":"dev","label":"Dev","passwordEnv":"MCPGODEBUG"}]`, env: map[string]string{"MCPGODEBUG": secret}},
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
	if _, err := loaded.Executor().ForProfile("missing"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("ForProfile(unknown profile) error = %v, want ErrProfileNotFound", err)
	}
}

func executorForProfile(t *testing.T, executor Executor, profileID string) ProfileExecutor {
	t.Helper()
	bound, err := executor.ForProfile(profileID)
	if err != nil {
		t.Fatalf("ForProfile(%q) error = %v", profileID, err)
	}
	return bound
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
