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
	sessionHandler := a.Sessions.LoadAndSave(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := sessionTokenFromRequest(r, a.Config.Session.CookieName)
		unlock, err := a.acquireSessionLock(r.Context(), token)
		if err != nil {
			a.Sessions.ErrorFunc(w, r, err)
			return
		}
		defer unlock()
		sessionHandler.ServeHTTP(w, r.WithContext(withSessionLock(r.Context(), token)))
	})
}

func (a *Authenticator) Logout(ctx context.Context) error {
	if a == nil || a.Config.Mode == config.AuthModeOff || a.Sessions == nil {
		return nil
	}
	token := a.Sessions.Token(ctx)
	unlock, err := a.acquireSessionLock(ctx, token)
	if err != nil {
		return err
	}
	defer unlock()
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
