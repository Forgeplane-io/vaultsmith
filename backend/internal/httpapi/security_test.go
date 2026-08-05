package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func csrfTestConfig() config.AuthConfig {
	return config.AuthConfig{
		Mode:    config.AuthModeOff,
		CSRF:    config.CSRFConfig{Secret: strings.Repeat("c", 32)},
		Session: config.SessionConfig{Secure: false, SameSite: http.SameSiteLaxMode},
		OIDC:    config.OIDCConfig{PublicBaseURL: "http://example.test"},
	}
}

func TestCSRFMiddlewareIssuesAndValidatesSharedSecretToken(t *testing.T) {
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CSRFToken(r) == "" {
			t.Error("CSRFToken() is empty inside handler")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	wrapped := WrapSecurity(base, csrfTestConfig())

	get := httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/session", nil)
	get.Host = "example.test"
	getResponse := httptest.NewRecorder()
	wrapped.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusNoContent {
		t.Fatalf("GET status = %d, want %d", getResponse.Code, http.StatusNoContent)
	}
	cookies := getResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("CSRF cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "vaultsmith_csrf" || cookie.Path != "/" || cookie.HttpOnly || cookie.Domain != "" || cookie.Secure {
		t.Fatalf("unexpected CSRF cookie: %#v", cookie)
	}

	post := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/profiles/dev/encrypt", nil)
	post.Host = "example.test"
	post.AddCookie(cookie)
	post.Header.Set("Origin", "http://example.test")
	post.Header.Set("X-CSRF-Token", cookie.Value)
	postResponse := httptest.NewRecorder()
	wrapped.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusNoContent {
		t.Fatalf("POST status = %d, want %d", postResponse.Code, http.StatusNoContent)
	}
}

func TestCSRFRejectsMissingTokenAndForeignOrigin(t *testing.T) {
	base := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	wrapped := WrapSecurity(base, csrfTestConfig())

	for name, mutate := range map[string]func(*http.Request){
		"missing header": func(r *http.Request) { r.Header.Set("Origin", "http://example.test") },
		"foreign origin": func(r *http.Request) {
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("X-CSRF-Token", "not-a-token")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://example.test/mutate", nil)
			request.Host = "example.test"
			cookie := &http.Cookie{Name: "vaultsmith_csrf", Value: "invalid"}
			request.AddCookie(cookie)
			mutate(request)
			response := httptest.NewRecorder()
			wrapped.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
		})
	}
}

func TestCORSUsesExactAllowlistAndHandlesPreflight(t *testing.T) {
	cfg := csrfTestConfig()
	cfg.CORS.AllowedOrigins = []string{"https://client.example"}
	wrapped := WrapSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), cfg)

	request := httptest.NewRequest(http.MethodOptions, "http://example.test/api", nil)
	request.Host = "example.test"
	request.Header.Set("Origin", "https://client.example")
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Fatalf("allow-origin = %q", got)
	}

	bad := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)
	bad.Host = "example.test"
	bad.Header.Set("Origin", "https://client.example.evil")
	badResponse := httptest.NewRecorder()
	wrapped.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d, want %d", badResponse.Code, http.StatusForbidden)
	}
}
