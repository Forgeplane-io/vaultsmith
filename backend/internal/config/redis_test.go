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

func TestLoadAuthRedisAcceptsTCPAddresses(t *testing.T) {
	maximumHostname := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	tests := []struct {
		name    string
		address string
	}{
		{name: "hostname", address: "redis-cache.example.test:6379"},
		{name: "fully qualified hostname", address: "redis.example.test.:6379"},
		{name: "IPv4", address: "192.0.2.10:6379"},
		{name: "bracketed IPv6", address: "[2001:db8::10]:6379"},
		{name: "maximum port", address: "redis.example.test:65535"},
		{name: "maximum hostname", address: maximumHostname + ":6379"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := nativeEnv()
			values["REDIS_ADDR"] = test.address
			cfg, err := LoadAuth(envLookup(values))
			if err != nil {
				t.Fatal("LoadAuth() rejected a valid REDIS_ADDR")
			}
			if cfg.Redis.Address != test.address {
				t.Fatal("LoadAuth() did not preserve the valid REDIS_ADDR")
			}
		})
	}
}

func TestLoadAuthRedisRejectsMalformedAddressesWithoutEchoing(t *testing.T) {
	const wantError = "REDIS_ADDR must be a credential-free TCP host:port"
	overlongHostname := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, ".")
	tests := []struct {
		name    string
		address string
	}{
		{name: "URI", address: "redis://uri-marker.example.test:6379"},
		{name: "user info", address: "userinfo-marker@redis.example.test:6379"},
		{name: "missing host", address: ":6379"},
		{name: "missing port", address: "missing-port-marker.example.test"},
		{name: "empty port", address: "empty-port-marker.example.test:"},
		{name: "zero port", address: "zero-port-marker.example.test:0"},
		{name: "out of range port", address: "range-port-marker.example.test:65536"},
		{name: "non-numeric port", address: "service-port-marker.example.test:redis"},
		{name: "signed port", address: "signed-port-marker.example.test:+6379"},
		{name: "leading whitespace", address: " leading-space-marker.example.test:6379"},
		{name: "trailing whitespace", address: "trailing-space-marker.example.test:6379 "},
		{name: "embedded whitespace", address: "embedded space-marker.example.test:6379"},
		{name: "control character", address: "control-marker.example.test:\n6379"},
		{name: "path", address: "path-marker.example.test/cache:6379"},
		{name: "query", address: "query-marker.example.test?db=0:6379"},
		{name: "fragment", address: "fragment-marker.example.test#cache:6379"},
		{name: "unbracketed IPv6", address: "2001:db8::10:6379"},
		{name: "bracketed hostname", address: "[bracketed-host-marker.example.test]:6379"},
		{name: "malformed bracketed IPv6", address: "[2001:db8::gg]:6379"},
		{name: "hostname punctuation", address: "host-marker!.example.test:6379"},
		{name: "empty hostname label", address: "empty-label-marker..example.test:6379"},
		{name: "leading hostname hyphen", address: "-leading-hyphen-marker.example.test:6379"},
		{name: "trailing hostname hyphen", address: "trailing-hyphen-marker-.example.test:6379"},
		{name: "overlong hostname label", address: strings.Repeat("a", 64) + ".example.test:6379"},
		{name: "overlong hostname", address: overlongHostname + ":6379"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := nativeEnv()
			values["REDIS_ADDR"] = test.address
			_, err := LoadAuth(envLookup(values))
			if err == nil {
				t.Fatal("LoadAuth() error = nil, want REDIS_ADDR validation")
			}
			if err.Error() != wantError {
				t.Fatal("LoadAuth() returned an unsafe or unexpected REDIS_ADDR error")
			}
		})
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
