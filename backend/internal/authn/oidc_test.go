package authn

import (
	"context"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func TestSafeReturnToAllowsOnlyInternalPaths(t *testing.T) {
	allowed := []string{"/", "/profiles", "/profiles?selected=dev", "/api/v1/profiles#top"}
	for _, value := range allowed {
		if got, err := safeReturnTo(value); err != nil || got != value {
			t.Fatalf("safeReturnTo(%q) = (%q, %v), want unchanged", value, got, err)
		}
	}

	rejected := []string{"", "https://evil.example", "//evil.example", `\\evil.example`, "/\x00"}
	for _, value := range rejected {
		if _, err := safeReturnTo(value); err == nil {
			t.Fatalf("safeReturnTo(%q) error = nil, want rejection", value)
		}
	}
}

func TestNewAuthenticatorOffSkipsRedisAndOIDC(t *testing.T) {
	values := map[string]string{
		"AUTH_MODE":   "off",
		"CSRF_SECRET": strings.Repeat("c", 32),
	}
	cfg, err := config.LoadAuth(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("LoadAuth() error = %v", err)
	}
	service, err := NewAuthenticator(context.Background(), *cfg, nil)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	if service.Redis != nil || service.Provider != nil {
		t.Fatalf("off-mode service initialized external dependencies: %+v", service)
	}
}

func TestSafeReturnToRejectsControlAndEncodedExternalTargets(t *testing.T) {
	for _, value := range []string{"/%2f%2fevil.example", "/\nnext"} {
		if _, err := safeReturnTo(value); err == nil {
			t.Fatalf("safeReturnTo(%q) error = nil, want rejection", value)
		}
	}
}
