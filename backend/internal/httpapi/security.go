package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

type Dependencies struct {
	Auth       *authn.Authenticator
	Authorizer *authz.Authorizer
	AuthConfig config.AuthConfig
}

func NewWithDependencies(profiles []Profile, executor Executor, dependencies Dependencies) http.Handler {
	handler := newHandler(profiles, executor)
	handler.auth = dependencies.Auth
	handler.authorizer = dependencies.Authorizer
	handler.authConfig = dependencies.AuthConfig
	return handler
}

func WrapSecurity(next http.Handler, cfg config.AuthConfig) http.Handler {
	if cfg.Mode == config.AuthModeNative {
		next = csrfMiddleware(next, cfg)
	}
	next = corsMiddleware(next, cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

const nativeCSRFCookieName = "__Host-vaultsmith_csrf"

func csrfCookieName(cfg config.AuthConfig) string {
	if cfg.Mode == config.AuthModeNative {
		return nativeCSRFCookieName
	}
	return "vaultsmith_csrf"
}

func corsMiddleware(next http.Handler, cfg config.AuthConfig) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.CORS.AllowedOrigins))
	for _, origin := range cfg.CORS.AllowedOrigins {
		allowed[origin] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		_, explicitlyAllowed := allowed[origin]
		sameOrigin := isSameOrigin(origin, r, cfg)
		if !explicitlyAllowed && !sameOrigin {
			writeError(w, http.StatusForbidden, "cors_forbidden", "origin is not allowed")
			return
		}
		if explicitlyAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions && explicitlyAllowed {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(origin string, r *http.Request, cfg config.AuthConfig) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	expected := requestOrigin(r)
	if cfg.OIDC.PublicBaseURL != "" {
		base, baseErr := url.Parse(cfg.OIDC.PublicBaseURL)
		if baseErr != nil || base.Scheme == "" || base.Host == "" {
			return false
		}
		expected = base.Scheme + "://" + base.Host
	}
	return strings.EqualFold(parsed.Scheme+"://"+parsed.Host, expected)
}

func requestOrigin(r *http.Request) string {
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if proto == "" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	return proto + "://" + r.Host
}

func (h *Handler) requirePrincipal(r *http.Request) (authn.Principal, bool, int, string) {
	if h.auth == nil || h.authorizer == nil {
		return authn.Principal{}, false, http.StatusServiceUnavailable, "not_ready"
	}
	principal, found, err := h.auth.AuthenticatedPrincipal(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, authn.ErrNotAuthenticated), errors.Is(err, authn.ErrRefreshRequired):
			return authn.Principal{}, false, http.StatusUnauthorized, "unauthorized"
		case errors.Is(err, authn.ErrTemporaryUnavailable):
			return authn.Principal{}, false, http.StatusServiceUnavailable, "temporarily_unavailable"
		default:
			return authn.Principal{}, false, http.StatusUnauthorized, "unauthorized"
		}
	}
	if !found {
		return authn.Principal{}, false, http.StatusUnauthorized, "unauthorized"
	}
	return principal, true, 0, ""
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	message := "request could not be authenticated"
	if status == http.StatusServiceUnavailable {
		message = "service is temporarily unavailable"
	}
	writeError(w, status, code, message)
}

func authURLReturnTo(r *http.Request) string {
	value := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if value == "" {
		return "/"
	}
	return value
}
