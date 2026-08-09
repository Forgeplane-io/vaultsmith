package httpapi

import (
	"errors"
	"net/http"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func (h *Handler) serveSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	response := sessionResponse{CSRFToken: CSRFToken(r), AuthRequired: h.authConfig.Mode == config.AuthModeNative}
	if h.authConfig.Mode == config.AuthModeNative {
		if h.auth == nil {
			writeAuthError(w, http.StatusServiceUnavailable, "not_ready")
			return
		}
		principal, found, err := h.auth.AuthenticatedPrincipal(r.Context())
		if err != nil {
			switch {
			case errors.Is(err, authn.ErrNotAuthenticated), errors.Is(err, authn.ErrRefreshRequired):
			case errors.Is(err, authn.ErrTemporaryUnavailable):
				writeAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
				return
			default:
				writeAuthError(w, http.StatusServiceUnavailable, "not_ready")
				return
			}
		}
		if found {
			response.Authenticated = true
			if principal.EmailVerified {
				response.Email = principal.Email
			}
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.authConfig.Mode != config.AuthModeNative || h.auth == nil {
		writeAuthError(w, http.StatusServiceUnavailable, "not_ready")
		return
	}
	location, err := h.auth.BeginLogin(r.Context(), authURLReturnTo(r))
	if err != nil {
		if errors.Is(err, authn.ErrTemporaryUnavailable) {
			writeAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "login request is invalid")
		}
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (h *Handler) serveCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.authConfig.Mode != config.AuthModeNative || h.auth == nil {
		writeAuthError(w, http.StatusServiceUnavailable, "not_ready")
		return
	}
	location, err := h.auth.CompleteLogin(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		authn.ClearSessionCookie(w, h.authConfig.Session)
		if errors.Is(err, authn.ErrTemporaryUnavailable) {
			writeAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		} else {
			writeError(w, http.StatusUnauthorized, "authentication_failed", "authentication could not be completed")
		}
		return
	}
	if location == "" {
		location = "/"
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (h *Handler) serveLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if h.auth != nil {
		if err := h.auth.Logout(r.Context()); err != nil {
			writeAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
	}
	authn.ClearSessionCookie(w, h.authConfig.Session)
	w.WriteHeader(http.StatusNoContent)
}
