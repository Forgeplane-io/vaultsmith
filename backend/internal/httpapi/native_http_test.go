package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

type recordingExecutor struct {
	called bool
}

func (e *recordingExecutor) Execute(string, string, string) (string, error) {
	e.called = true
	return "ok", nil
}

func (e *recordingExecutor) Rotate(string, string, string) (string, error) {
	e.called = true
	return "rotated", nil
}

func writeNativePolicy(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.csv")
	content := "g, group:admins, role:admin\n" +
		"p, role:admin, profiles, profiles:list, allow\n" +
		"p, role:admin, profile:dev, encrypt, allow\n" +
		"p, role:admin, profile:dev, decrypt, allow\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func nativeHTTPFixture(t *testing.T) (http.Handler, *authn.Authenticator, config.AuthConfig, string, *recordingExecutor) {
	t.Helper()
	server := miniredis.RunT(t)
	redisConfig := config.RedisConfig{
		Address:          server.Addr(),
		KeyPrefix:        "http-test:",
		ConnectTimeout:   time.Second,
		ReadTimeout:      time.Second,
		WriteTimeout:     time.Second,
		PoolSize:         4,
		RefreshLockTTL:   500 * time.Millisecond,
		RefreshLockWait:  100 * time.Millisecond,
		RefreshLockRetry: 10 * time.Millisecond,
		ProviderTimeout:  100 * time.Millisecond,
	}
	runtime, err := authn.NewRedisRuntime(redisConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	cfg := config.AuthConfig{
		Mode:    config.AuthModeNative,
		OIDC:    config.OIDCConfig{PublicBaseURL: "https://example.test", GroupsClaim: "groups"},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour, IdleLifetime: time.Minute, Secure: true, SameSite: http.SameSiteLaxMode},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
		Redis:   redisConfig,
	}
	authenticator := &authn.Authenticator{Config: cfg, Redis: runtime, Sessions: authn.NewSessionManager(runtime.SessionStore(), cfg.Session)}
	policy, err := authz.LoadPolicy(writeNativePolicy(t), []string{"dev", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}, {ID: "prod", Label: "Production"}}, executor, Dependencies{Auth: authenticator, Authorizer: authorizer, AuthConfig: cfg, Ready: true})
	return authenticator.SessionMiddleware(WrapSecurity(api, cfg)), authenticator, cfg, server.Addr(), executor
}

func seedNativeSession(t *testing.T, authenticator *authn.Authenticator) string {
	t.Helper()
	ctx, err := authenticator.Sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	authn.StorePrincipal(ctx, authenticator.Sessions, authn.Principal{Issuer: "https://issuer", Subject: "subject", Groups: []string{"admins"}, Email: "user@example.test", EmailVerified: true, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}, "")
	token, _, err := authenticator.Sessions.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestNativeHTTPAuthenticationAuthorizationAndSessionBootstrap(t *testing.T) {
	handler, authenticator, cfg, _, executor := nativeHTTPFixture(t)
	unauthenticated := httptest.NewRecorder()
	unauthenticatedRequest := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/profiles", nil)
	handler.ServeHTTP(unauthenticated, unauthenticatedRequest)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated profiles status = %d, want 401: %s", unauthenticated.Code, unauthenticated.Body.String())
	}

	sessionToken := seedNativeSession(t, authenticator)

	bootstrap := httptest.NewRecorder()
	bootstrapRequest := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/session", nil)
	bootstrapRequest.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	handler.ServeHTTP(bootstrap, bootstrapRequest)
	if bootstrap.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d, want 200: %s", bootstrap.Code, bootstrap.Body.String())
	}
	var session sessionResponse
	if err := json.Unmarshal(bootstrap.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if !session.Authenticated || !session.AuthRequired || session.CSRFToken == "" {
		t.Fatalf("bootstrap session = %+v, want authenticated native session and CSRF token", session)
	}
	var csrfCookie *http.Cookie
	for _, cookie := range bootstrap.Result().Cookies() {
		if cookie.Name == csrfCookieName(cfg) {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatalf("bootstrap did not issue CSRF cookie")
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/profiles", nil)
	request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	request.AddCookie(csrfCookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() == "" {
		t.Fatalf("profiles response = %d %s", response.Code, response.Body.String())
	}
	if response.Body.String() != `{"profiles":[{"id":"dev","label":"Development"}]}
` {
		t.Fatalf("profiles response = %q, want only authorized dev profile", response.Body.String())
	}

	authorized := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"secret"}`))
	authorized.Header.Set("Content-Type", "application/json")
	authorized.Header.Set("Origin", "https://example.test")
	authorized.Header.Set("Referer", "https://example.test/")
	authorized.Header.Set(csrfHeaderName, session.CSRFToken)
	authorized.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	authorized.AddCookie(csrfCookie)
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorized)
	if authorizedResponse.Code != http.StatusOK || authorizedResponse.Body.String() != `{"value":"ok"}
` {
		t.Fatalf("authorized operation response = %d %s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	if !executor.called {
		t.Fatal("executor was not called for authorized operation")
	}

	executor.called = false
	forbidden := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/operations", strings.NewReader(`{"profileId":"prod","mode":"encrypt","value":"secret"}`))
	forbidden.Header.Set("Content-Type", "application/json")
	forbidden.Header.Set("Origin", "https://example.test")
	forbidden.Header.Set("Referer", "https://example.test/")
	forbidden.Header.Set(csrfHeaderName, session.CSRFToken)
	forbidden.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	forbidden.AddCookie(csrfCookie)
	forbiddenResponse := httptest.NewRecorder()
	handler.ServeHTTP(forbiddenResponse, forbidden)
	if forbiddenResponse.Code != http.StatusForbidden {
		t.Fatalf("forbidden operation status = %d, want 403: %s", forbiddenResponse.Code, forbiddenResponse.Body.String())
	}
	if executor.called {
		t.Fatal("executor was called for forbidden operation")
	}
}
