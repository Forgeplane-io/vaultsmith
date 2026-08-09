package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func nativeEnv() map[string]string {
	return map[string]string{
		"AUTH_MODE":            "native",
		"OIDC_ISSUER_URL":      "https://id.example.test/realms/vaultsmith",
		"OIDC_CLIENT_ID":       "vaultsmith",
		"OIDC_CLIENT_SECRET":   "client-secret-value",
		"OIDC_REDIRECT_URL":    "https://vaultsmith.example.test/auth/callback",
		"PUBLIC_BASE_URL":      "https://vaultsmith.example.test",
		"REDIS_ADDR":           "redis.example.test:6379",
		"REDIS_KEY_PREFIX":     "vaultsmith:prod:",
		"CSRF_SECRET":          strings.Repeat("c", 32),
		"AUTHZ_POLICY_FILE":    "/etc/vaultsmith/policy.csv",
		"CORS_ALLOWED_ORIGINS": "https://vaultsmith.example.test",
	}
}

func TestLoadAuthRequiresExplicitMode(t *testing.T) {
	if _, err := LoadAuth(envLookup(map[string]string{})); err == nil || !strings.Contains(err.Error(), "AUTH_MODE") {
		t.Fatalf("LoadAuth() error = %v, want explicit AUTH_MODE error", err)
	}
}

func TestLoadAuthOffDoesNotRequireCSRFSecret(t *testing.T) {
	cfg, err := LoadAuth(envLookup(map[string]string{"AUTH_MODE": "off"}))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v, want nil", err)
	}
	if cfg.CSRF.Secret != "" {
		t.Fatalf("CSRF secret = %q, want empty in off mode", cfg.CSRF.Secret)
	}
}

func TestLoadAuthNativeRequiresCSRFSecret(t *testing.T) {
	values := nativeEnv()
	delete(values, "CSRF_SECRET")
	_, err := LoadAuth(envLookup(values))
	if err == nil || !strings.Contains(err.Error(), "CSRF_SECRET") {
		t.Fatalf("LoadAuth() error = %v, want missing CSRF_SECRET", err)
	}
}

func TestLoadAuthNativeRequiresOIDCClientSecret(t *testing.T) {
	values := nativeEnv()
	delete(values, "OIDC_CLIENT_SECRET")
	_, err := LoadAuth(envLookup(values))
	if err == nil {
		t.Fatal("LoadAuth() error = nil, want missing OIDC_CLIENT_SECRET")
	}
	if !strings.Contains(err.Error(), "OIDC_CLIENT_SECRET") {
		t.Fatalf("error = %q, want OIDC_CLIENT_SECRET", err)
	}
}

func TestLoadAuthNativeParsesDefaultsAndOptionalRedisAuth(t *testing.T) {
	values := nativeEnv()
	values["REDIS_USERNAME"] = "vaultsmith"
	values["REDIS_PASSWORD"] = "redis-secret-value"
	values["REDIS_TLS"] = "true"
	values["OIDC_SCOPES"] = "openid profile offline_access email"
	values["OIDC_GROUPS_CLAIM"] = "realm_access.groups"
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if cfg.Mode != AuthModeNative {
		t.Fatalf("mode = %q, want native", cfg.Mode)
	}
	if cfg.OIDC.GroupsClaim != "realm_access.groups" {
		t.Fatalf("groups claim = %q", cfg.OIDC.GroupsClaim)
	}
	if len(cfg.OIDC.Scopes) != 4 || cfg.OIDC.Scopes[2] != "offline_access" {
		t.Fatalf("scopes = %#v", cfg.OIDC.Scopes)
	}
	if !cfg.Redis.TLS || cfg.Redis.Username != "vaultsmith" || cfg.Redis.Password != "redis-secret-value" {
		t.Fatalf("redis auth/TLS = %#v", cfg.Redis)
	}
	if cfg.Session.AbsoluteLifetime != 8*time.Hour || cfg.Session.IdleLifetime != 30*time.Minute {
		t.Fatalf("session lifetimes = %s/%s", cfg.Session.AbsoluteLifetime, cfg.Session.IdleLifetime)
	}
}

func TestLoadAuthRejectsUnsafeNativeCookieAndCORSCombinations(t *testing.T) {
	tests := []struct {
		name  string
		patch map[string]string
		want  string
	}{
		{
			name:  "http issuer",
			patch: map[string]string{"OIDC_ISSUER_URL": "http://id.example.test"},
			want:  "OIDC_ISSUER_URL",
		},
		{
			name:  "http public base",
			patch: map[string]string{"PUBLIC_BASE_URL": "http://vaultsmith.example.test"},
			want:  "PUBLIC_BASE_URL",
		},
		{
			name:  "wildcard origin",
			patch: map[string]string{"CORS_ALLOWED_ORIGINS": "*"},
			want:  "CORS_ALLOWED_ORIGINS",
		},
		{
			name:  "non-loopback HTTP origin",
			patch: map[string]string{"COOKIE_SAME_SITE": "none", "CORS_ALLOWED_ORIGINS": "http://portal.example.test"},
			want:  "CORS_ALLOWED_ORIGINS",
		},
		{
			name:  "same-site none without cross-origin",
			patch: map[string]string{"COOKIE_SAME_SITE": "none", "CORS_ALLOWED_ORIGINS": ""},
			want:  "COOKIE_SAME_SITE",
		},
		{
			name:  "same-site strict for native callback",
			patch: map[string]string{"COOKIE_SAME_SITE": "strict"},
			want:  "COOKIE_SAME_SITE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := nativeEnv()
			for key, value := range tt.patch {
				values[key] = value
			}
			_, err := LoadAuth(envLookup(values))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadAuth() error = %v, want mention %s", err, tt.want)
			}
		})
	}
}

func TestLoadAuthAllowsLoopbackHTTPCORSForDevelopment(t *testing.T) {
	values := nativeEnv()
	values["COOKIE_SAME_SITE"] = "none"
	values["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000"
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if len(cfg.CORS.AllowedOrigins) != 1 || cfg.CORS.AllowedOrigins[0] != "http://localhost:3000" {
		t.Fatalf("allowed origins = %#v, want loopback development origin", cfg.CORS.AllowedOrigins)
	}
}

func TestLoadAuthPreservesCanonicalOIDCIssuer(t *testing.T) {
	values := nativeEnv()
	values["OIDC_ISSUER_URL"] = "https://id.example.test/realms/vaultsmith/"
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if cfg.OIDC.IssuerURL != values["OIDC_ISSUER_URL"] {
		t.Fatalf("OIDC issuer = %q, want configured canonical issuer %q", cfg.OIDC.IssuerURL, values["OIDC_ISSUER_URL"])
	}
}

func TestLoadAuthRejectsInvalidDurationWithoutEchoingValue(t *testing.T) {
	values := nativeEnv()
	values["SESSION_IDLE_LIFETIME"] = "invalid-secret-like-value"
	_, err := LoadAuth(envLookup(values))
	if err == nil {
		t.Fatal("LoadAuth() error = nil, want invalid duration")
	}
	if strings.Contains(err.Error(), "invalid-secret-like-value") {
		t.Fatalf("error leaked raw value: %q", err)
	}
}

func TestLoadAuthNativeAcceptsOIDCCAFile(t *testing.T) {
	caFile := t.TempDir() + "/issuer-ca.pem"
	if err := os.WriteFile(caFile, []byte("test PEM bundle"), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	values := nativeEnv()
	values["OIDC_CA_FILE"] = caFile
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if cfg.OIDC.CAFile != caFile {
		t.Fatalf("OIDC CA file = %q, want %q", cfg.OIDC.CAFile, caFile)
	}
}

func TestLoadAuthNativeRejectsMissingOIDCCAFile(t *testing.T) {
	values := nativeEnv()
	values["OIDC_CA_FILE"] = t.TempDir() + "/missing-ca.pem"
	_, err := LoadAuth(envLookup(values))
	if err == nil || !strings.Contains(err.Error(), "OIDC_CA_FILE") {
		t.Fatalf("LoadAuth() error = %v, want OIDC_CA_FILE", err)
	}
}
