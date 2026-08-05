package config

import (
	"strings"
	"testing"
)

func TestLoadAuthRedisAllowsNoCredentials(t *testing.T) {
	values := nativeEnv()
	delete(values, "REDIS_USERNAME")
	delete(values, "REDIS_PASSWORD")
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if cfg.Redis.Username != "" || cfg.Redis.Password != "" {
		t.Fatalf("redis credentials = %q/%q, want omitted", cfg.Redis.Username, cfg.Redis.Password)
	}
	if cfg.Redis.CredentialsConfigured() {
		t.Fatal("CredentialsConfigured() = true, want false")
	}
}

func TestLoadAuthRedisRejectsUsernameWithoutPassword(t *testing.T) {
	values := nativeEnv()
	values["REDIS_USERNAME"] = "vaultsmith"
	delete(values, "REDIS_PASSWORD")
	_, err := LoadAuth(envLookup(values))
	if err == nil || !strings.Contains(err.Error(), "REDIS_PASSWORD") {
		t.Fatalf("LoadAuth() error = %v, want REDIS_PASSWORD", err)
	}
}

func TestLoadAuthRedisRejectsUnsafePrefix(t *testing.T) {
	for _, prefix := range []string{"", " ", "vaultsmith", "vaultsmith\n", "vaultsmith:*"} {
		values := nativeEnv()
		values["REDIS_KEY_PREFIX"] = prefix
		_, err := LoadAuth(envLookup(values))
		if err == nil {
			t.Fatalf("LoadAuth(%q) error = nil, want invalid prefix", prefix)
		}
	}
}
