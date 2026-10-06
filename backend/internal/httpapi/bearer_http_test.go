package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type bearerIssuerFixture struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	kid         string
	jwksHandler func(http.ResponseWriter, *http.Request)
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
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if fixture.jwksHandler != nil {
			fixture.jwksHandler(w, r)
			return
		}
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

func TestNativeBearerJWKSTrustExpiry(t *testing.T) {
	for _, transport := range []string{"REST", "MCP"} {
		for _, policy := range []struct {
			name, cache, age string
			outageStatus     int
		}{
			{name: "absent stale", cache: "max-age=1", outageStatus: http.StatusServiceUnavailable},
			{name: "zero stale", cache: "max-age=1, stale-if-error=0", outageStatus: http.StatusServiceUnavailable},
			{name: "malformed stale", cache: "max-age=1, stale-if-error=invalid", outageStatus: http.StatusServiceUnavailable},
			{name: "signed stale", cache: "max-age=1, stale-if-error=+60", outageStatus: http.StatusServiceUnavailable},
			{name: "unbalanced stale", cache: `max-age=1, stale-if-error="60`, outageStatus: http.StatusServiceUnavailable},
			{name: "explicit stale", cache: "max-age=1, stale-if-error=60", outageStatus: http.StatusOK},
			{name: "zero freshness explicit stale", cache: "max-age=0, stale-if-error=60", outageStatus: http.StatusOK},
			{name: "consumed freshness explicit stale", cache: "max-age=1, stale-if-error=60", age: "2", outageStatus: http.StatusOK},
		} {
			t.Run(transport+"/"+policy.name, func(t *testing.T) {
				handler, issuer, _ := bearerHTTPFixtureWithMCP(t, true)
				var state atomic.Int32
				var calls atomic.Int32
				issuer.jwksHandler = func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					if state.Load() == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Header().Set("Cache-Control", policy.cache)
					if policy.age != "" {
						w.Header().Set("Age", policy.age)
					}
					keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &issuer.key.PublicKey, KeyID: issuer.kid, Algorithm: string(jose.RS256), Use: "sig"}}}
					if state.Load() == 2 {
						keys.Keys = []jose.JSONWebKey{}
					}
					_ = json.NewEncoder(w).Encode(keys)
				}
				server := httptest.NewTLSServer(handler)
				t.Cleanup(server.Close)
				token := issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeProfileRead+" "+vaultservice.ScopeEncrypt)
				request := func(wantStatus int) {
					t.Helper()
					method, path, body := http.MethodGet, "/api/v1/profiles", ""
					if transport == "MCP" {
						method, path = http.MethodPost, "/mcp"
						body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_profiles","arguments":{},` + mcpMeta + `}}`
					}
					req, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer "+token)
					if transport == "MCP" {
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set("Accept", "application/json, text/event-stream")
						req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
						req.Header.Set("Mcp-Method", "tools/call")
						req.Header.Set("Mcp-Name", "list_profiles")
					}
					response, err := server.Client().Do(req)
					if err != nil {
						t.Fatal("native TLS request failed")
					}
					defer response.Body.Close()
					data, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal("native response read failed")
					}
					if response.StatusCode != wantStatus {
						t.Fatalf("status = %d, want %d", response.StatusCode, wantStatus)
					}
					if wantStatus == http.StatusOK && !strings.Contains(string(data), "dev") {
						t.Fatal("successful server outcome did not list authorized profile")
					}
					if wantStatus == http.StatusServiceUnavailable && !strings.Contains(string(data), "temporarily_unavailable") {
						t.Fatal("outage did not return safe unavailable error")
					}
					if wantStatus == http.StatusUnauthorized && !strings.Contains(response.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
						t.Fatal("removed key did not receive invalid-token challenge")
					}
					if strings.Contains(string(data), token) || len(response.Cookies()) != 0 {
						t.Fatal("Bearer response leaked credentials or issued cookies")
					}
				}
				request(http.StatusOK)
				if calls.Load() != 1 {
					t.Fatal("initial request did not fetch current JWKS")
				}
				state.Store(1)
				// Cross the server's at-most-one-second freshness without a
				// cache-field assertion or a production clock hook.
				time.Sleep(time.Second)
				request(policy.outageStatus)
				if calls.Load() != 2 {
					t.Fatal("expired request did not revalidate JWKS")
				}
				state.Store(2)
				request(http.StatusUnauthorized)
				if calls.Load() != 3 {
					t.Fatal("removed-key control did not fetch replacement JWKS")
				}
				t.Logf("native TLS %s: current-key profile success, outage status=%d, successful key removal=401", transport, policy.outageStatus)
			})
		}
	}
}

// A denied preflight must finish without installing the application deadline.
type deadlineTrackingContext struct {
	context.Context
	queried bool
}

func (c *deadlineTrackingContext) Deadline() (time.Time, bool) {
	c.queried = true
	return c.Context.Deadline()
}

func TestNativeBearerCanonicalOperationSkipsCSRFAndSessionCookies(t *testing.T) {
	handler, issuer, executor := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", strings.NewReader(`{"plaintext":"synthetic"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", "vaultsmith.encrypt"))
	response := httptest.NewRecorder()

	started := time.Now()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if !executor.called {
		t.Fatal("executor was not called")
	}
	deadline, ok := executor.ctx.Deadline()
	if !ok || deadline.Before(started.Add(30*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatal("authorized execution did not receive the 30-second application deadline")
	}
	if cookies := response.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("bearer response issued cookies: %#v", cookies)
	}
}

func TestNativeBearerMissingAndInsufficientScopeChallengeBeforeBodyRead(t *testing.T) {
	handler, issuer, _ := bearerHTTPFixture(t)
	// Populate JWKS before observing only the application's deadline setup.
	warm := httptest.NewRequest(http.MethodGet, "https://vaultsmith.example.test/api/v1/profiles", nil)
	warm.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeProfileRead))
	warmResponse := httptest.NewRecorder()
	handler.ServeHTTP(warmResponse, warm)
	if warmResponse.Code != http.StatusOK {
		t.Fatalf("JWKS warm-up status = %d, want 200", warmResponse.Code)
	}
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
			ctx := &deadlineTrackingContext{Context: request.Context()}
			request = request.WithContext(ctx)
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
			if !strings.Contains(response.Header().Get("WWW-Authenticate"), `resource_metadata="https://vaultsmith.example.test/.well-known/oauth-protected-resource"`) {
				t.Fatalf("WWW-Authenticate = %q, want canonical resource metadata URL", response.Header().Get("WWW-Authenticate"))
			}
			if body.read {
				t.Fatal("body was read before bearer challenge")
			}
			if ctx.queried {
				t.Fatal("application deadline was installed before the bearer challenge")
			}
		})
	}
}

func TestNativeBearerGenerateReadinessPrecedesDeadline(t *testing.T) {
	issuer := newBearerIssuerFixture(t)
	cfg := config.AuthConfig{
		Mode: config.AuthModeNative,
		OIDC: config.OIDCConfig{IssuerURL: issuer.server.URL, PublicBaseURL: "https://vaultsmith.example.test", GroupsClaim: "groups"},
	}
	verifier, err := authn.NewAccessTokenVerifier(context.Background(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := issuer.token(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeEncrypt)
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	authenticator := &authn.Authenticator{Config: cfg, Access: verifier}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, nil, Dependencies{Auth: authenticator, AuthConfig: cfg})
	handler := WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator, MCPEnabled: true})
	for _, path := range []string{"/api/v1/generate", "/mcp"} {
		t.Run(path, func(t *testing.T) {
			body := &trackingReader{}
			request := httptest.NewRequest(http.MethodPost, cfg.OIDC.PublicBaseURL+path, body)
			ctx := &deadlineTrackingContext{Context: request.Context()}
			request = request.WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+token)
			if path == "/mcp" {
				request.Header.Set("Accept", "application/json, text/event-stream")
				request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
				request.Header.Set("Mcp-Method", "tools/call")
				request.Header.Set("Mcp-Name", "generate_token")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"not_ready"`) {
				t.Fatalf("readiness response = %d, want 503 not_ready", response.Code)
			}
			if body.read || ctx.queried || response.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("readiness denial read the body, installed a deadline, or issued a scope challenge")
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
