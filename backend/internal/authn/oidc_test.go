package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func TestOIDCHTTPClientUsesProviderTimeout(t *testing.T) {
	timeout := 25 * time.Millisecond
	client, err := newOIDCHTTPClient("", timeout)
	if err != nil {
		t.Fatalf("newOIDCHTTPClient() error = %v", err)
	}
	if client == nil || client.Timeout != timeout {
		t.Fatalf("OIDC HTTP client timeout = %v, want %v", client.Timeout, timeout)
	}
}

func TestOIDCHTTPClientRejectsRedirects(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("OIDC client followed a redirect")
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	t.Cleanup(source.Close)

	client, err := newOIDCHTTPClient("", time.Second)
	if err != nil {
		t.Fatalf("newOIDCHTTPClient() error = %v", err)
	}
	client.Transport = source.Client().Transport
	response, err := client.Get(source.URL)
	if err != nil {
		t.Fatalf("GET redirect response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d, want %d", response.StatusCode, http.StatusFound)
	}
}

func TestLoadOIDCComponentsFetchesAndUsesOneStrictDiscoveryDocument(t *testing.T) {
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		suffix := "first"
		if call > 1 {
			suffix = "unexpected-second"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/jwks-" + suffix,
			"authorization_endpoint":                server.URL + "/authorize-" + suffix,
			"token_endpoint":                        server.URL + "/token-" + suffix,
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(server.Close)

	access, provider, err := loadOIDCComponents(
		context.Background(),
		server.URL,
		server.URL,
		"groups",
		server.Client(),
		server.Client(),
	)
	if err != nil {
		t.Fatalf("loadOIDCComponents() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("discovery requests = %d, want 1", got)
	}
	if access.jwksURL != server.URL+"/jwks-first" {
		t.Fatalf("access JWKS URL = %q", access.jwksURL)
	}
	endpoint := provider.Endpoint()
	if endpoint.AuthURL != server.URL+"/authorize-first" || endpoint.TokenURL != server.URL+"/token-first" {
		t.Fatalf("provider endpoint = %#v, want first discovery response", endpoint)
	}
}

func TestSafeReturnToAllowsOnlyInternalPaths(t *testing.T) {
	allowed := []string{"/", "/profiles", "/profiles?selected=dev", "/api/v1/profiles#top"}
	for _, value := range allowed {
		if got, err := safeReturnTo(value); err != nil || got != value {
			t.Fatalf("safeReturnTo(%q) = (%q, %v), want unchanged", value, got, err)
		}
	}

	rejected := []string{"", "https://evil.example", "//evil.example", `\\evil.example`, "/\x00", "/%2f%2fevil.example", "/\nnext"}
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
	if service == nil || service.Sessions != nil {
		t.Fatalf("off-mode authenticator initialized a session manager: %+v", service)
	}
}
