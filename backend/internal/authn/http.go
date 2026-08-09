package authn

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

// SessionMiddleware is an SCS LoadAndSave equivalent with a lease fence before
// every session commit. SCS commits when a response is first written, so the
// fence must live in the response writer rather than only after the handler.
func (a *Authenticator) SessionMiddleware(next http.Handler) http.Handler {
	if a == nil || a.Sessions == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Cookie")
		token := sessionTokenFromRequest(r, a.Config.Session.CookieName)
		lock, err := a.acquireSessionMutex(r.Context(), token)
		if err != nil {
			a.Sessions.ErrorFunc(w, r, err)
			return
		}
		defer lock.release()

		ctx, err := a.Sessions.Load(lock.ctx, token)
		if err != nil {
			a.Sessions.ErrorFunc(w, r, err)
			return
		}
		loadedToken := a.Sessions.Token(ctx)
		if lock.fence != "" && loadedToken == token {
			if err := a.activateSessionFence(lock.ctx, token, lock.fence); err != nil {
				a.Sessions.ErrorFunc(w, r, err)
				return
			}
			a.Sessions.Put(ctx, sessionFenceKey, lock.fence)
		} else {
			// A stale cookie can refer to a session that has expired or been
			// evicted. SCS creates a new session with a new token in that case,
			// so the fence acquired for the old token must not be carried into
			// the replacement session.
			lock.fence = ""
		}
		ctx = withSessionLock(ctx, token, lock.fence, lock.healthy)
		sr := r.WithContext(ctx)
		sw := &sessionResponseWriter{
			ResponseWriter: w,
			request:        sr,
			sessionManager: a.Sessions,
		}
		next.ServeHTTP(sw, sr)
		_ = sw.ensureSessionCommitted()
	})
}

type sessionResponseWriter struct {
	http.ResponseWriter
	request         *http.Request
	sessionManager  *scs.SessionManager
	commitAttempted bool
	commitSucceeded bool
}

func (sw *sessionResponseWriter) commitAndWriteSessionCookie() bool {
	if !sessionLockHealthy(sw.request.Context()) {
		sw.sessionManager.ErrorFunc(sw.ResponseWriter, sw.request, ErrTemporaryUnavailable)
		return false
	}

	switch sw.sessionManager.Status(sw.request.Context()) {
	case scs.Modified:
		token, expiry, err := sw.sessionManager.Commit(sw.request.Context())
		if err != nil {
			sw.sessionManager.ErrorFunc(sw.ResponseWriter, sw.request, err)
			return false
		}
		sw.sessionManager.WriteSessionCookie(sw.request.Context(), sw.ResponseWriter, token, expiry)
	case scs.Destroyed:
		sw.sessionManager.WriteSessionCookie(sw.request.Context(), sw.ResponseWriter, "", time.Time{})
	}
	return true
}

func (sw *sessionResponseWriter) ensureSessionCommitted() bool {
	if sw.commitAttempted {
		return sw.commitSucceeded
	}
	sw.commitAttempted = true
	sw.commitSucceeded = sw.commitAndWriteSessionCookie()
	return sw.commitSucceeded
}

func (sw *sessionResponseWriter) WriteHeader(code int) {
	if !sw.ensureSessionCommitted() {
		return
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *sessionResponseWriter) Write(body []byte) (int, error) {
	if !sw.ensureSessionCommitted() {
		return 0, context.Canceled
	}
	return sw.ResponseWriter.Write(body)
}

func (sw *sessionResponseWriter) Flush() {
	if !sw.ensureSessionCommitted() {
		return
	}
	_ = http.NewResponseController(sw.ResponseWriter).Flush()
}

func (sw *sessionResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(sw.ResponseWriter).Hijack()
}

func (sw *sessionResponseWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}

func (a *Authenticator) Logout(ctx context.Context) error {
	if a == nil || a.Config.Mode == config.AuthModeOff || a.Sessions == nil {
		return nil
	}
	token := a.Sessions.Token(ctx)
	if token == "" {
		return nil
	}
	lock, err := a.acquireSessionLock(ctx, token)
	if err != nil {
		return err
	}
	defer lock.release()
	return a.Sessions.Destroy(withSessionLock(lock.ctx, token, lock.fence, lock.healthy))
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
