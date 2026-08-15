package config

import (
	"strings"
	"testing"
)

func TestLoadProofsDisabledByDefault(t *testing.T) {
	cfg, err := LoadProofs(envLookup(map[string]string{}))
	if err != nil {
		t.Fatalf("LoadProofs() error = %v", err)
	}
	if cfg.Enabled || cfg.KeyringFile != "" || cfg.Issuer != "" {
		t.Fatalf("disabled proofs config = %#v", cfg)
	}
}

func TestLoadProofsEnabledRequiresKeyringAndCanonicalHTTPSOrigin(t *testing.T) {
	base := map[string]string{"PROOFS_ENABLED": "true"}
	if _, err := LoadProofs(envLookup(base)); err == nil || !strings.Contains(err.Error(), "PROOFS_KEYRING_FILE") {
		t.Fatalf("missing keyring error = %v", err)
	}
	base["PROOFS_KEYRING_FILE"] = "/etc/vaultsmith/attestation-keyring.json"
	if _, err := LoadProofs(envLookup(base)); err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") {
		t.Fatalf("missing public base error = %v", err)
	}
	base["PUBLIC_BASE_URL"] = "HTTPS://VAULTSMITH.EXAMPLE.TEST/"
	cfg, err := LoadProofs(envLookup(base))
	if err != nil {
		t.Fatalf("LoadProofs() error = %v", err)
	}
	if !cfg.Enabled || cfg.KeyringFile != "/etc/vaultsmith/attestation-keyring.json" || cfg.Issuer != "https://vaultsmith.example.test" {
		t.Fatalf("proofs config = %#v", cfg)
	}
}

func TestLoadProofsRejectsInvalidEnabledValuesAndOrigins(t *testing.T) {
	tests := []struct {
		name  string
		patch map[string]string
		want  string
	}{
		{name: "invalid enabled", patch: map[string]string{"PROOFS_ENABLED": "yes"}, want: "PROOFS_ENABLED"},
		{name: "http origin", patch: map[string]string{"PUBLIC_BASE_URL": "http://vaultsmith.example.test"}, want: "PUBLIC_BASE_URL"},
		{name: "path origin", patch: map[string]string{"PUBLIC_BASE_URL": "https://vaultsmith.example.test/app"}, want: "PUBLIC_BASE_URL"},
		{name: "query origin", patch: map[string]string{"PUBLIC_BASE_URL": "https://vaultsmith.example.test/?x=1"}, want: "PUBLIC_BASE_URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]string{
				"PROOFS_ENABLED":      "true",
				"PROOFS_KEYRING_FILE": "/etc/vaultsmith/keyring.json",
				"PUBLIC_BASE_URL":     "https://vaultsmith.example.test",
			}
			for key, value := range tt.patch {
				values[key] = value
			}
			if _, err := LoadProofs(envLookup(values)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadProofs() error = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestLoadProofsDoesNotRequirePublicBaseWhenDisabled(t *testing.T) {
	cfg, err := LoadProofs(envLookup(map[string]string{"PROOFS_ENABLED": "false"}))
	if err != nil {
		t.Fatalf("LoadProofs() error = %v", err)
	}
	if cfg.Enabled {
		t.Fatal("disabled proofs were enabled")
	}
}

func TestLoadApplicationPreservesProofIssuerInAuthOffMode(t *testing.T) {
	values := map[string]string{
		"AUTH_MODE":           "off",
		"VAULT_PROFILES_JSON": `[{"id":"dev","label":"Development","passwordEnv":"VAULT_DEV_PASSWORD"}]`,
		"VAULT_DEV_PASSWORD":  "synthetic-password",
		"PROOFS_ENABLED":      "true",
		"PROOFS_KEYRING_FILE": "/etc/vaultsmith/keyring.json",
		"PUBLIC_BASE_URL":     "HTTPS://VAULTSMITH.EXAMPLE.TEST/",
		"MCP_ENABLED":         "false",
	}
	loaded, err := loadApplication(envLookup(values))
	if err != nil {
		t.Fatalf("loadApplication() error = %v", err)
	}
	if got := loaded.Proofs(); !got.Enabled || got.Issuer != "https://vaultsmith.example.test" {
		t.Fatalf("proofs config = %#v", got)
	}
	if got := loaded.Auth().OIDC.PublicBaseURL; got != "https://vaultsmith.example.test" {
		t.Fatalf("auth public base = %q", got)
	}
}
