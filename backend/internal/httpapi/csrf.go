package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

const (
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenBytes = 32
)

type csrfContextKey struct{}

func CSRFToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	token, _ := r.Context().Value(csrfContextKey{}).(string)
	return token
}

func csrfMiddleware(next http.Handler, cfg config.AuthConfig) http.Handler {
	secret := []byte(cfg.CSRF.Secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Cookie")
		cookie, err := r.Cookie(csrfCookieName(cfg))
		token := ""
		validCookie := false
		if err == nil {
			token = cookie.Value
			validCookie = validCSRFToken(secret, token)
		}
		if !validCookie {
			var issueErr error
			token, issueErr = issueCSRFToken(secret)
			if issueErr != nil {
				writeError(w, http.StatusServiceUnavailable, "csrf_unavailable", "service is temporarily unavailable")
				return
			}
			setCSRFCookie(w, cfg, token)
		}
		r = r.WithContext(contextWithCSRFToken(r.Context(), token))
		if safeCSRFMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !validCookie || !csrfOriginAllowed(r, cfg) || !hmac.Equal([]byte(token), []byte(r.Header.Get(csrfHeaderName))) {
			writeError(w, http.StatusForbidden, "csrf_failed", "request could not be verified")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func contextWithCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfContextKey{}, token)
}

func safeCSRFMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func issueCSRFToken(secret []byte) (string, error) {
	nonce := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(nonce)
	value := append(nonce, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validCSRFToken(secret []byte, token string) bool {
	value, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(value) != csrfTokenBytes+sha256.Size {
		return false
	}
	nonce := value[:csrfTokenBytes]
	provided := value[csrfTokenBytes:]
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(nonce)
	return hmac.Equal(provided, mac.Sum(nil))
}

func setCSRFCookie(w http.ResponseWriter, cfg config.AuthConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName(cfg),
		Value:    token,
		Path:     "/",
		Secure:   cfg.Session.Secure,
		HttpOnly: false,
		SameSite: cfg.Session.SameSite,
	})
}

func csrfOriginAllowed(r *http.Request, cfg config.AuthConfig) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != "null" {
		if isSameOrigin(origin, r, cfg) {
			return true
		}
		for _, allowed := range cfg.CORS.AllowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return false
	}
	referer := strings.TrimSpace(r.Referer())
	if referer == "" {
		return false
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return isSameOrigin(parsed.Scheme+"://"+parsed.Host, r, cfg)
}
