package authn

import (
	"context"
	"net/http"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func (a *Authenticator) SessionMiddleware(next http.Handler) http.Handler {
	if a == nil || a.Sessions == nil {
		return next
	}
	return a.Sessions.LoadAndSave(next)
}

func (a *Authenticator) Logout(ctx context.Context) error {
	if a == nil || a.Config.Mode == config.AuthModeOff || a.Sessions == nil {
		return nil
	}
	return a.Sessions.Destroy(ctx)
}

func ClearSessionCookie(w http.ResponseWriter, cfg config.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     "/",
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
		MaxAge:   -1,
	})
}
