package config

import (
	"strings"
	"testing"
	"time"
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

func TestLoadAuthRedisLoadsRefreshTuning(t *testing.T) {
	values := nativeEnv()
	values["REDIS_REFRESH_LOCK_TTL"] = "45s"
	values["REDIS_REFRESH_LOCK_WAIT"] = "2s"
	values["REDIS_REFRESH_LOCK_RETRY"] = "100ms"
	values["REDIS_PROVIDER_TIMEOUT"] = "30s"
	cfg, err := LoadAuth(envLookup(values))
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	if cfg.Redis.RefreshLockTTL != 45*time.Second || cfg.Redis.RefreshLockWait != 2*time.Second || cfg.Redis.RefreshLockRetry != 100*time.Millisecond || cfg.Redis.ProviderTimeout != 30*time.Second {
		t.Fatalf("redis refresh tuning = %+v", cfg.Redis)
	}
}

func TestLoadAuthRedisRejectsRefreshLockTTLNotExceedingProviderTimeout(t *testing.T) {
	values := nativeEnv()
	values["REDIS_REFRESH_LOCK_TTL"] = "10s"
	values["REDIS_PROVIDER_TIMEOUT"] = "10s"
	if _, err := LoadAuth(envLookup(values)); err == nil || !strings.Contains(err.Error(), "REDIS_REFRESH_LOCK_TTL") {
		t.Fatalf("LoadAuth() error = %v, want TTL validation", err)
	}
}
