package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type bearerIssuerFixture struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newBearerIssuerFixture(t *testing.T) *bearerIssuerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &bearerIssuerFixture{key: key, kid: "kid-1"}
	publicKey := jose.JSONWebKey{Key: &key.PublicKey, KeyID: fixture.kid, Algorithm: string(jose.RS256), Use: "sig"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 fixture.server.URL,
			"jwks_uri":               fixture.server.URL + "/jwks",
			"authorization_endpoint": fixture.server.URL + "/authorize",
			"token_endpoint":         fixture.server.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
	})
	fixture.server = httptest.NewTLSServer(mux)
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *bearerIssuerFixture) token(t *testing.T, audience, scope string) string {
	return f.tokenWithGroups(t, audience, scope, []string{"admins"})
}

func (f *bearerIssuerFixture) tokenWithGroups(t *testing.T, audience, scope string, groups []string) string {
	t.Helper()
	now := time.Now().UTC()
	options := (&jose.SignerOptions{}).WithType("at+jwt")
	options.WithHeader(jose.HeaderKey("kid"), f.kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:    f.server.URL,
		Subject:   "subject",
		Audience:  jwt.Audience{audience},
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ID:        "synthetic-jti",
	}).Claims(map[string]any{
		"client_id": "vaultsmith-ci",
		"scope":     scope,
		"groups":    groups,
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bearerHTTPFixtureWithMCP(t *testing.T, mcpEnabled bool) (http.Handler, *bearerIssuerFixture, *recordingExecutor) {
	t.Helper()
	issuer := newBearerIssuerFixture(t)
	cfg := config.AuthConfig{
		Mode:    config.AuthModeNative,
		OIDC:    config.OIDCConfig{IssuerURL: issuer.server.URL, PublicBaseURL: "https://vaultsmith.example.test", GroupsClaim: "groups"},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour, IdleLifetime: time.Minute, Secure: true, SameSite: http.SameSiteLaxMode},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
	}
	verifier, err := authn.NewAccessTokenVerifier(context.Background(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &authn.Authenticator{Config: cfg, Access: verifier}
	policyPath := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyPath, []byte("g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, encrypt, allow\np, role:admin, profile:dev, decrypt, allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := authz.LoadPolicy(policyPath, []string{"dev"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, executor, Dependencies{Auth: authenticator, Authorizer: authorizer, AuthConfig: cfg})
	return WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator, MCPEnabled: mcpEnabled}), issuer, executor
}

func bearerHTTPFixture(t *testing.T) (http.Handler, *bearerIssuerFixture, *recordingExecutor) {
	return bearerHTTPFixtureWithMCP(t, false)
}

func TestNativeBearerCanonicalOperationSkipsCSRFAndSessionCookies(t *testing.T) {
	handler, issuer, executor := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", strings.NewReader(`{"plaintext":"synthetic"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", "vaultsmith.encrypt"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if !executor.called {
		t.Fatal("executor was not called")
	}
	if cookies := response.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("bearer response issued cookies: %#v", cookies)
	}
}

func TestNativeBearerMissingAndInsufficientScopeChallengeBeforeBodyRead(t *testing.T) {
	handler, issuer, _ := bearerHTTPFixture(t)
	for _, test := range []struct {
		name          string
		authorization string
		status        int
		wantChallenge string
	}{
		{name: "missing token", status: http.StatusUnauthorized, wantChallenge: `Bearer realm="vaultsmith", scope="vaultsmith.encrypt"`},
		{name: "missing scope", authorization: "Bearer " + issuer.token(t, "https://vaultsmith.example.test", "vaultsmith.profile.read"), status: http.StatusForbidden, wantChallenge: `error="insufficient_scope", scope="vaultsmith.encrypt"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReader{}
			request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", body)
			request.Header.Set("Content-Type", "application/json")
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if !strings.Contains(response.Header().Get("WWW-Authenticate"), test.wantChallenge) {
				t.Fatalf("WWW-Authenticate = %q, want contain %q", response.Header().Get("WWW-Authenticate"), test.wantChallenge)
			}
			if body.read {
				t.Fatal("body was read before bearer challenge")
			}
		})
	}
}

func TestOffModeAuthorizationHeaderRejectedWithoutBearerChallenge(t *testing.T) {
	cfg := config.AuthConfig{Mode: config.AuthModeOff, CORS: config.CORSConfig{AllowedOrigins: []string{"https://vaultsmith.example.test"}}}
	handler := WrapSecurityWithOptions(newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}), cfg, SecurityOptions{})
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", strings.NewReader(`{"plaintext":"synthetic"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer ignored")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty", response.Header().Get("WWW-Authenticate"))
	}
}

func TestNativeRESTCORSExposesBearerChallengeHeaders(t *testing.T) {
	handler, _, _ := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodOptions, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", nil)
	request.Header.Set("Origin", "https://vaultsmith.example.test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("Access-Control-Allow-Headers = %q", response.Header().Get("Access-Control-Allow-Headers"))
	}
	if got := response.Header().Get("Access-Control-Expose-Headers"); got != "WWW-Authenticate, X-Request-ID, Retry-After" {
		t.Fatalf("Access-Control-Expose-Headers = %q", got)
	}
}
