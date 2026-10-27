package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type recordingExecutor struct {
	called bool
	ctx    context.Context
}

type recordingProfileExecutor struct {
	owner *recordingExecutor
}

func (e *recordingExecutor) ForProfile(string) (vaultservice.ProfileExecutor, error) {
	return &recordingProfileExecutor{owner: e}, nil
}

func (e *recordingProfileExecutor) Encrypt(ctx context.Context, _ string) (string, error) {
	e.owner.called = true
	e.owner.ctx = ctx
	return "ok", nil
}

func (e *recordingProfileExecutor) Decrypt(context.Context, string) (string, error) {
	e.owner.called = true
	return "plaintext", nil
}

func writeNativePolicy(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.csv")
	content := "g, group:admins, role:admin\n" +
		"p, role:admin, profiles, profiles:list, allow\n" +
		"p, role:admin, profile:dev, encrypt, allow\n" +
		"p, role:admin, profile:dev, decrypt, allow\n" +
		"p, role:admin, profile:read, decrypt, allow\n"
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
		OIDC:    config.OIDCConfig{IssuerURL: "https://issuer", ClientID: "browser-client", PublicBaseURL: "https://example.test", GroupsClaim: "groups"},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour, IdleLifetime: time.Minute, Secure: true, SameSite: http.SameSiteLaxMode},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
		Redis:   redisConfig,
	}
	authenticator := &authn.Authenticator{Config: cfg, Redis: runtime, Sessions: authn.NewSessionManager(runtime.SessionStore(), cfg.Session)}
	policyPath := writeNativePolicy(t)
	policy, err := authz.LoadPolicy(policyPath, []string{"dev", "prod", "read"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}, {ID: "prod", Label: "Production"}, {ID: "read", Label: "Read only"}}, executor, Dependencies{Auth: authenticator, Authorizer: authorizer, AuthConfig: cfg})
	return WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator}), authenticator, cfg, policyPath, executor
}

func seedNativeSession(t *testing.T, authenticator *authn.Authenticator, requestedGroups ...string) string {
	t.Helper()
	groups := []string{"admins"}
	if len(requestedGroups) > 0 {
		groups = requestedGroups
	}
	ctx, err := authenticator.Sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	authn.StorePrincipal(ctx, authenticator.Sessions, authn.Principal{Issuer: authenticator.Config.OIDC.IssuerURL, Subject: "subject", Groups: groups, Email: "user@example.test", ExpiresAt: time.Now().Add(time.Hour)}, "", authenticator.Config.OIDC)
	token, _, err := authenticator.Sessions.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func delegatedHTTPFixture(t *testing.T) (http.Handler, *authn.Authenticator, config.AuthConfig, *bearerIssuerFixture, *fakeExecutor, string) {
	t.Helper()
	_, authenticator, cfg, _, _ := nativeHTTPFixture(t)
	issuer := newBearerIssuerFixture(t)
	cfg.OIDC.IssuerURL = issuer.server.URL
	authenticator.Config = cfg
	verifier, err := authn.NewAccessTokenVerifier(t.Context(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
	if err != nil {
		t.Fatal("construct synthetic access verifier failed")
	}
	authenticator.Access = verifier
	profiles := []Profile{{ID: "y", Label: "Y"}, {ID: "a", Label: "A"}, {ID: "x", Label: "X"}, {ID: "b", Label: "B"}, {ID: "direct", Label: "Direct"}, {ID: "hidden", Label: "Hidden"}}
	ids := make([]string, len(profiles))
	serviceProfiles := make([]vaultservice.Profile, len(profiles))
	for index, profile := range profiles {
		ids[index] = profile.ID
		serviceProfiles[index] = vaultservice.Profile{ID: profile.ID, Label: profile.Label}
	}
	content := "g, group:delegates, role:delegate\np, role:delegate, profiles, profiles:list, allow\n" +
		"p, role:delegate, rotation:a:x, rotate, allow\np, role:delegate, rotation:b:y, rotate, allow\n" +
		"p, role:delegate, rotation:a:y, rotate, allow\np, role:delegate, rotation:a:y, rotate, deny\n" +
		"p, role:delegate, rotation:hidden:x, rotate, allow\np, role:delegate, rotation:hidden:x, rotate, deny\n" +
		"p, role:delegate, profile:a, decrypt, deny\np, role:delegate, profile:x, encrypt, deny\n" +
		"p, role:delegate, profile:direct, encrypt, allow\np, role:delegate, profile:direct, decrypt, allow\n" +
		"g, group:old, role:old\np, role:old, profiles, profiles:list, allow\np, role:old, profile:a, decrypt, allow\np, role:old, profile:x, encrypt, allow\n"
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal("write synthetic delegated policy failed")
	}
	policy, err := authz.LoadPolicy(path, ids)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	executor := &fakeExecutor{value: "synthetic output", decryptedValue: "synthetic plaintext"}
	service := vaultservice.NewWithOptions(serviceProfiles, executor, authorizer, nil, vaultservice.ServiceOptions{AttestationEnabled: true, AttestationManager: newHTTPSyntheticAttestationManager(cfg.OIDC.PublicBaseURL)})
	api := NewWithDependencies(profiles, executor, Dependencies{Service: service, Auth: authenticator, AuthConfig: cfg})
	return WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator, MCPEnabled: true}), authenticator, cfg, issuer, executor, path
}

const delegatedLaneProfilesJSON = `{"profiles":[{"id":"y","label":"Y","capabilities":{"encrypt":false,"decrypt":false,"rotateSource":false,"rotateDestination":true,"rotateDestinationIds":[]}},{"id":"a","label":"A","capabilities":{"encrypt":false,"decrypt":false,"rotateSource":true,"rotateDestination":false,"rotateDestinationIds":["x"]}},{"id":"x","label":"X","capabilities":{"encrypt":false,"decrypt":false,"rotateSource":false,"rotateDestination":true,"rotateDestinationIds":[]}},{"id":"b","label":"B","capabilities":{"encrypt":false,"decrypt":false,"rotateSource":true,"rotateDestination":false,"rotateDestinationIds":["y"]}}]}`

func TestDelegatedDiscoveryRESTAndMCPPreserveExactOrderedRelations(t *testing.T) {
	handler, authenticator, cfg, issuer, executor, _ := delegatedHTTPFixture(t)
	withDirect := strings.TrimSuffix(delegatedLaneProfilesJSON, "]}") + `,{"id":"direct","label":"Direct","capabilities":{"encrypt":true,"decrypt":true,"rotateSource":false,"rotateDestination":false,"rotateDestinationIds":[]}}]}`
	for _, test := range []struct {
		name, group, scopes, expected string
	}{
		{name: "rotate only", group: "delegates", scopes: vaultservice.ScopeProfileRead + " " + vaultservice.ScopeRotate, expected: delegatedLaneProfilesJSON},
		{name: "direct scopes without rotate", group: "delegates", scopes: vaultservice.ScopeProfileRead + " " + vaultservice.ScopeEncrypt + " " + vaultservice.ScopeDecrypt, expected: `{"profiles":[{"id":"direct","label":"Direct","capabilities":{"encrypt":true,"decrypt":true,"rotateSource":false,"rotateDestination":false,"rotateDestinationIds":[]}}]}`},
		{name: "profile read only", group: "delegates", scopes: vaultservice.ScopeProfileRead, expected: `{"profiles":[]}`},
		{name: "all scopes", group: "delegates", scopes: vaultservice.ScopeProfileRead + " " + vaultservice.ScopeRotate + " " + vaultservice.ScopeEncrypt + " " + vaultservice.ScopeDecrypt, expected: withDirect},
		{name: "old direct policy", group: "old", scopes: vaultservice.ScopeProfileRead + " " + vaultservice.ScopeRotate + " " + vaultservice.ScopeEncrypt + " " + vaultservice.ScopeDecrypt, expected: `{"profiles":[{"id":"a","label":"A","capabilities":{"encrypt":false,"decrypt":true,"rotateSource":false,"rotateDestination":false,"rotateDestinationIds":[]}},{"id":"x","label":"X","capabilities":{"encrypt":true,"decrypt":false,"rotateSource":false,"rotateDestination":false,"rotateDestinationIds":[]}}]}`},
		{name: "unknown group", group: "unknown", scopes: vaultservice.ScopeProfileRead + " " + vaultservice.ScopeRotate, expected: `{"profiles":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, test.scopes, []string{test.group})
			request := httptest.NewRequest(http.MethodGet, cfg.OIDC.PublicBaseURL+"/api/v1/profiles", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || len(response.Result().Cookies()) != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("REST discovery status = %d, want private 200 without cookies", response.Code)
			}
			assertDiscoveryJSON(t, response.Body.Bytes(), test.expected)
			request = newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_profiles","arguments":{},`+mcpMeta+`}}`)
			request.Header.Set("Mcp-Name", "list_profiles")
			request.Header.Set("Authorization", "Bearer "+token)
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || len(response.Result().Cookies()) != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("MCP discovery status = %d, want private 200 without cookies", response.Code)
			}
			assertMCPDiscoveryJSON(t, response, test.expected)
		})
	}
	request := httptest.NewRequest(http.MethodGet, cfg.OIDC.PublicBaseURL+"/api/v1/profiles", nil)
	request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: seedNativeSession(t, authenticator, "delegates")})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session discovery status = %d, want 200", response.Code)
	}
	assertDiscoveryJSON(t, response.Body.Bytes(), withDirect)
	if len(executor.calls) != 0 {
		t.Fatal("discovery executed Vault work")
	}
}

func TestDelegatedRotationsKeepRESTLegacyAndMCPAuthorizationBoundaries(t *testing.T) {
	handler, authenticator, cfg, issuer, executor, _ := delegatedHTTPFixture(t)
	sessions := map[string]string{"delegates": seedNativeSession(t, authenticator, "delegates"), "old": seedNativeSession(t, authenticator, "old")}
	tokens := map[string]string{"delegates": issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeRotate, []string{"delegates"}), "old": issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeRotate, []string{"old"})}
	csrf, err := issueCSRFToken([]byte(cfg.CSRF.Secret))
	if err != nil {
		t.Fatal("issue synthetic CSRF token failed")
	}
	for _, transport := range []string{"REST session", "legacy session", "REST Bearer", "MCP Bearer"} {
		for _, test := range []struct {
			name, group, source, destination string
			allowed                          bool
		}{
			{name: "first lane", group: "delegates", source: "a", destination: "x", allowed: true},
			{name: "second lane", group: "delegates", source: "b", destination: "y", allowed: true},
			{name: "crossed denied pair", group: "delegates", source: "a", destination: "y"},
			{name: "reverse", group: "delegates", source: "x", destination: "a"},
			{name: "unrelated", group: "delegates", source: "a", destination: "b"},
			{name: "unknown", group: "delegates", source: "missing", destination: "x"},
			{name: "old no-lane policy", group: "old", source: "a", destination: "x"},
		} {
			t.Run(transport+"/"+test.name, func(t *testing.T) {
				arguments := `{"sourceProfileId":"` + test.source + `","destinationProfileId":"` + test.destination + `","vaultText":"synthetic input"}`
				path, body := "/api/v1/rotations", arguments
				if transport == "legacy session" {
					path, body = "/api/v1/operations", `{"mode":"rotate","sourceProfileId":"`+test.source+`","destinationProfileId":"`+test.destination+`","value":"synthetic input"}`
				}
				request := httptest.NewRequest(http.MethodPost, cfg.OIDC.PublicBaseURL+path, strings.NewReader(body))
				if transport == "MCP Bearer" {
					request = newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rotate","arguments":`+arguments+`,`+mcpMeta+`}}`)
					request.Header.Set("Mcp-Name", "rotate")
				}
				request.Header.Set("Content-Type", "application/json")
				if strings.HasSuffix(transport, "Bearer") {
					request.Header.Set("Authorization", "Bearer "+tokens[test.group])
				} else {
					request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessions[test.group]})
					request.AddCookie(&http.Cookie{Name: csrfCookieName(cfg), Value: csrf})
					request.Header.Set(csrfHeaderName, csrf)
					request.Header.Set("Origin", cfg.OIDC.PublicBaseURL)
				}
				executor.calls = nil
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if !test.allowed {
					if response.Code != http.StatusForbidden || response.Body.String() != "{\"error\":{\"code\":\"forbidden\",\"message\":\"operation is not permitted\"}}\n" || len(executor.calls) != 0 || response.Header().Get("WWW-Authenticate") != "" {
						t.Fatalf("denied rotation status = %d, want generic 403 without execution or challenge", response.Code)
					}
					return
				}
				if response.Code != http.StatusOK || len(executor.calls) != 2 || executor.calls[0].profileID != test.source || executor.calls[1].profileID != test.destination || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("allowed rotation status = %d, want exact private server outcome", response.Code)
				}
			})
		}
	}
}

func TestDelegatedGrantsDoNotRelaxCredentialOrScopePreflight(t *testing.T) {
	handler, authenticator, cfg, issuer, executor, _ := delegatedHTTPFixture(t)
	session := seedNativeSession(t, authenticator, "delegates")
	token := issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeRotate, []string{"delegates"})
	wrongScope := issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeDecrypt+" "+vaultservice.ScopeEncrypt, []string{"delegates"})
	for _, test := range []struct {
		name, path, bearer string
		session            bool
		status             int
	}{
		{name: "canonical missing CSRF", path: "/api/v1/rotations", session: true, status: http.StatusForbidden},
		{name: "legacy missing CSRF", path: "/api/v1/operations", session: true, status: http.StatusForbidden},
		{name: "legacy rejects Bearer", path: "/api/v1/operations", bearer: token, status: http.StatusUnauthorized},
		{name: "MCP rejects session", path: "/mcp", session: true, status: http.StatusUnauthorized},
		{name: "canonical mixed credentials", path: "/api/v1/rotations", session: true, bearer: token, status: http.StatusBadRequest},
		{name: "MCP mixed credentials", path: "/mcp", session: true, bearer: token, status: http.StatusBadRequest},
		{name: "canonical wrong scope", path: "/api/v1/rotations", bearer: wrongScope, status: http.StatusForbidden},
		{name: "MCP wrong scope", path: "/mcp", bearer: wrongScope, status: http.StatusForbidden},
		{name: "canonical missing credential", path: "/api/v1/rotations", status: http.StatusUnauthorized},
		{name: "MCP missing credential", path: "/mcp", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReader{}
			request := httptest.NewRequest(http.MethodPost, cfg.OIDC.PublicBaseURL+test.path, body)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", cfg.OIDC.PublicBaseURL)
			if test.path == "/mcp" {
				request.Header.Set("Accept", "application/json, text/event-stream")
				request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
				request.Header.Set("Mcp-Method", "tools/call")
				request.Header.Set("Mcp-Name", "rotate")
			}
			if test.session {
				request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: session})
			}
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || body.read || len(executor.calls) != 0 {
				t.Fatalf("credential/scope preflight status = %d, want %d without reading or execution", response.Code, test.status)
			}
		})
	}
}

func TestDelegatedLaneDoesNotGrantDirectOperationsOrGenerate(t *testing.T) {
	handler, _, cfg, issuer, executor, _ := delegatedHTTPFixture(t)
	token := issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeEncrypt+" "+vaultservice.ScopeDecrypt+" "+vaultservice.ScopeRotate, []string{"delegates"})
	for _, operation := range []struct{ name, path, body, arguments string }{
		{name: "encrypt", path: "/api/v1/profiles/x/encrypt", body: `{"plaintext":"synthetic input"}`, arguments: `{"profileId":"x","plaintext":"synthetic input"}`},
		{name: "decrypt", path: "/api/v1/profiles/a/decrypt", body: `{"vaultText":"synthetic input"}`, arguments: `{"profileId":"a","vaultText":"synthetic input"}`},
		{name: "generate_age_identity", path: "/api/v1/generate", body: `{"kind":"age_identity","profileId":"x","parameters":{}}`, arguments: `{"profileId":"x"}`},
	} {
		for _, transport := range []string{"REST", "MCP"} {
			t.Run(transport+"/"+operation.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, cfg.OIDC.PublicBaseURL+operation.path, strings.NewReader(operation.body))
				request.Header.Set("Content-Type", "application/json")
				if transport == "MCP" {
					request = newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+operation.name+`","arguments":`+operation.arguments+`,`+mcpMeta+`}}`)
					request.Header.Set("Mcp-Name", operation.name)
				}
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusForbidden || len(executor.calls) != 0 || decodeJSONBody[apimodels.ErrorResponse](t, response).Error.Message != "operation is not permitted" {
					t.Fatalf("lane-only direct operation status = %d, want safe 403 without execution", response.Code)
				}
			})
		}
	}
}

func TestDelegatedDiscoveryDenialIsEmptyButUnavailablePolicyIsAnError(t *testing.T) {
	for _, state := range []string{"empty", "denied", "invalid", "missing"} {
		t.Run(state, func(t *testing.T) {
			handler, _, cfg, issuer, _, path := delegatedHTTPFixture(t)
			if state == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal("remove synthetic policy failed")
				}
			} else {
				content := ""
				if state == "denied" {
					content = "g, group:delegates, role:delegate\np, role:delegate, profiles, profiles:list, deny\np, role:delegate, rotation:a:x, rotate, allow\n"
				} else if state == "invalid" {
					content = "p, role:delegate, rotation:a:missing, rotate, allow\n"
				}
				replacement := path + ".replacement"
				if err := os.WriteFile(replacement, []byte(content), 0o600); err != nil {
					t.Fatal("write synthetic replacement failed")
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal("publish synthetic replacement failed")
				}
			}
			token := issuer.tokenWithGroups(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeProfileRead+" "+vaultservice.ScopeRotate, []string{"delegates"})
			for _, transport := range []string{"REST", "MCP"} {
				request := httptest.NewRequest(http.MethodGet, cfg.OIDC.PublicBaseURL+"/api/v1/profiles", nil)
				if transport == "MCP" {
					request = newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_profiles","arguments":{},`+mcpMeta+`}}`)
					request.Header.Set("Mcp-Name", "list_profiles")
				}
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if state == "invalid" || state == "missing" {
					if response.Code != http.StatusServiceUnavailable || decodeJSONBody[apimodels.ErrorResponse](t, response).Error.Code != "not_ready" {
						t.Fatalf("%s unavailable discovery status = %d, want 503 not_ready", transport, response.Code)
					}
				} else {
					if response.Code != http.StatusOK {
						t.Fatalf("%s denied discovery status = %d, want 200", transport, response.Code)
					}
					if transport == "MCP" {
						assertMCPDiscoveryJSON(t, response, `{"profiles":[]}`)
					} else {
						assertDiscoveryJSON(t, response.Body.Bytes(), `{"profiles":[]}`)
					}
				}
			}
		})
	}
}

func TestNativeHTTPAuthorizedSessionCSRFAndProfileFiltering(t *testing.T) {
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
	profiles := decodeJSONBody[profilesResponse](t, response).Profiles
	wantProfiles := []apimodels.Profile{
		{Id: "dev", Label: "Development", Capabilities: apimodels.ProfileCapabilities{Encrypt: true, Decrypt: true, RotateDestinationIds: []string{}}},
		{Id: "read", Label: "Read only", Capabilities: apimodels.ProfileCapabilities{Decrypt: true, RotateDestinationIds: []string{}}},
	}
	if !reflect.DeepEqual(profiles, wantProfiles) {
		t.Fatalf("profiles = %#v, want authorized profiles with action capabilities %#v", profiles, wantProfiles)
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
	if authorizedResponse.Code != http.StatusOK || decodeJSONBody[valueResponse](t, authorizedResponse).Value != "ok" {
		t.Fatalf("authorized operation response = %d %s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	if !executor.called {
		t.Fatal("executor was not called for authorized operation")
	}

	missingCSRF := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"secret"}`))
	missingCSRF.Header.Set("Content-Type", "application/json")
	missingCSRF.Header.Set("Origin", "https://example.test")
	missingCSRF.Header.Set("Referer", "https://example.test/")
	missingCSRF.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	missingCSRF.AddCookie(csrfCookie)
	missingCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRFResponse, missingCSRF)
	if missingCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want 403: %s", missingCSRFResponse.Code, missingCSRFResponse.Body.String())
	}

	foreignOrigin := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"secret"}`))
	foreignOrigin.Header.Set("Content-Type", "application/json")
	foreignOrigin.Header.Set("Origin", "https://attacker.example")
	foreignOrigin.Header.Set(csrfHeaderName, session.CSRFToken)
	foreignOrigin.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	foreignOrigin.AddCookie(csrfCookie)
	foreignOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(foreignOriginResponse, foreignOrigin)
	if foreignOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d, want 403: %s", foreignOriginResponse.Code, foreignOriginResponse.Body.String())
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

	unknown := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/operations", strings.NewReader(`{"profileId":"missing","mode":"encrypt","value":"secret"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknown.Header.Set("Origin", "https://example.test")
	unknown.Header.Set("Referer", "https://example.test/")
	unknown.Header.Set(csrfHeaderName, session.CSRFToken)
	unknown.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken})
	unknown.AddCookie(csrfCookie)
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusForbidden {
		t.Fatalf("unknown profile status = %d, want 403: %s", unknownResponse.Code, unknownResponse.Body.String())
	}
}

func TestNativeHTTPProfileDenialReturnsEmptyResult(t *testing.T) {
	handler, authenticator, cfg, _, _ := nativeHTTPFixture(t)
	token := seedNativeSession(t, authenticator, "unknown")
	request := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/profiles", nil)
	request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: token})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if profiles := decodeJSONBody[profilesResponse](t, response).Profiles; len(profiles) != 0 {
		t.Fatalf("profiles = %#v, want empty result", profiles)
	}
}

func TestNativeHTTPPolicyFailureReturnsNotReady(t *testing.T) {
	handler, authenticator, cfg, policyPath, _ := nativeHTTPFixture(t)
	token := seedNativeSession(t, authenticator)
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/profiles", nil)
	request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: token})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
	body := decodeJSONBody[apimodels.ErrorResponse](t, response)
	if body.Error.Code != "not_ready" || strings.Contains(response.Body.String(), policyPath) {
		t.Fatalf("body = %#v", body)
	}
}

func TestSessionMiddlewareSerializesConcurrentSessionRequests(t *testing.T) {
	_, authenticator, cfg, _, _ := nativeHTTPFixture(t)
	token := seedNativeSession(t, authenticator)
	started := make(chan struct{})
	release := make(chan struct{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			close(started)
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	})
	wrapped := authenticator.SessionMiddleware(inner)

	first := httptest.NewRequest(http.MethodGet, "https://example.test/first", nil)
	first.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: token})
	firstResponse := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		wrapped.ServeHTTP(firstResponse, first)
		close(firstDone)
	}()
	<-started

	second := httptest.NewRequest(http.MethodGet, "https://example.test/second", nil)
	second.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: token})
	secondResponse := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() {
		wrapped.ServeHTTP(secondResponse, second)
		close(secondDone)
	}()
	select {
	case <-secondDone:
		t.Fatal("second session request completed while first request held the session lease")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-firstDone
	<-secondDone
	if firstResponse.Code != http.StatusNoContent || secondResponse.Code != http.StatusNoContent {
		t.Fatalf("serialized response statuses = %d/%d, want 204/204", firstResponse.Code, secondResponse.Code)
	}
}
