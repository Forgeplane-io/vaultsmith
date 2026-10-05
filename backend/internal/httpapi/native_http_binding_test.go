package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
)

// Set VAULTSMITH_TEST_REDIS_ADDR to a disposable Redis to repeat the HTTP
// authorization matrix against the real store; otherwise use miniredis.
func TestNativeHTTPSessionBoundaryReplay(t *testing.T) {
	for _, change := range []string{"unchanged", "issuer", "client", "resource", "legacy"} {
		t.Run(change, func(t *testing.T) {
			sourceHandler, source, cfg, policyPath, executor := nativeHTTPFixture(t)
			if address := os.Getenv("VAULTSMITH_TEST_REDIS_ADDR"); address != "" {
				cfg.Redis.Address = address
				runtime, err := authn.NewRedisRuntime(cfg.Redis)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = runtime.Close() })
				source.Redis = runtime
				source.Sessions = authn.NewSessionManager(runtime.SessionStore(), cfg.Session)
			}
			token := seedNativeSession(t, source)
			request := func(handler http.Handler) int {
				r := httptest.NewRequest(http.MethodGet, cfg.OIDC.PublicBaseURL+"/api/v1/profiles", nil)
				r.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: token})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w.Code
			}
			if got := request(sourceHandler); got != http.StatusOK {
				t.Fatalf("source authorization status=%d, want 200", got)
			}
			switch change {
			case "issuer":
				cfg.OIDC.IssuerURL = "https://other-issuer.test"
			case "client":
				cfg.OIDC.ClientID = "other-client"
			case "resource":
				cfg.OIDC.PublicBaseURL = "https://other-vault.test"
			case "legacy":
				if got := request(source.SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					source.Sessions.Remove(r.Context(), "auth.binding")
					w.WriteHeader(http.StatusOK)
				}))); got != http.StatusOK {
					t.Fatalf("legacy fixture update status=%d", got)
				}
			}
			// Separate relying party, identical Redis database and key prefix.
			target := &authn.Authenticator{Config: cfg, Redis: source.Redis, Sessions: authn.NewSessionManager(source.Redis.SessionStore(), cfg.Session)}
			policy, err := authz.LoadPolicy(policyPath, []string{"dev", "prod", "read"})
			if err != nil {
				t.Fatal(err)
			}
			authorizer, err := authz.NewAuthorizer(policy)
			if err != nil {
				t.Fatal(err)
			}
			api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, executor, Dependencies{Auth: target, Authorizer: authorizer, AuthConfig: cfg})
			handler := WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: target})
			want := http.StatusUnauthorized
			if change == "unchanged" {
				want = http.StatusOK
			}
			if got := request(handler); got != want {
				t.Fatalf("replay authorization status=%d, want %d", got, want)
			}
			if change != "unchanged" {
				if got := request(sourceHandler); got != http.StatusUnauthorized {
					t.Fatalf("original session survived invalidation: status=%d", got)
				}
			}
			t.Logf("source=200 replay=%d incompatible_session_destroyed=%t", want, change != "unchanged")
		})
	}
}
