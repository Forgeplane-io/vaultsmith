package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func TestRedisSessionFenceAllowsTokenRenewal(t *testing.T) {
	_, runtime, cfg := newTestRedisRuntime(t)

	sessionCfg := config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour}
	sessions := NewSessionManager(runtime.SessionStore(), sessionCfg)
	initial, err := sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	sessions.Put(initial, "marker", "initial")
	token, _, err := sessions.Commit(initial)
	if err != nil {
		t.Fatalf("initial Commit() error = %v", err)
	}
	authenticator := &Authenticator{
		Config:   config.AuthConfig{Mode: config.AuthModeNative, Session: sessionCfg, Redis: cfg},
		Redis:    runtime,
		Sessions: sessions,
	}
	lease, err := authenticator.acquireSessionLock(context.Background(), token)
	if err != nil {
		t.Fatalf("lease acquisition error = %v", err)
	}
	defer lease.release()
	ctx, err := sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("session Load() error = %v", err)
	}
	sessions.Put(ctx, sessionFenceKey, lease.fence)
	if _, _, err := sessions.Commit(ctx); err != nil {
		t.Fatalf("fenced Commit() error = %v", err)
	}
	ctx = withSessionLock(ctx, token, lease.fence, lease.healthy)
	if err := sessions.RenewToken(ctx); err != nil {
		t.Fatalf("fenced RenewToken() error = %v", err)
	}
	if got := sessions.Token(ctx); got == "" || got == token {
		t.Fatalf("renewed session token = %q, want a new token", got)
	}
}

func TestRedisSessionFenceRejectsStaleWholeSessionCommit(t *testing.T) {
	_, runtime, cfg := newTestRedisRuntime(t)

	sessionCfg := config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour}
	sessions := NewSessionManager(runtime.SessionStore(), sessionCfg)
	initial, err := sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	sessions.Put(initial, "marker", "initial")
	token, _, err := sessions.Commit(initial)
	if err != nil {
		t.Fatalf("initial Commit() error = %v", err)
	}

	authenticator := &Authenticator{
		Config:   config.AuthConfig{Mode: config.AuthModeNative, Session: sessionCfg, Redis: cfg},
		Redis:    runtime,
		Sessions: sessions,
	}
	leaseA, err := authenticator.acquireSessionLock(context.Background(), token)
	if err != nil {
		t.Fatalf("lease A acquisition error = %v", err)
	}
	ctxA, err := sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("lease A Load() error = %v", err)
	}
	sessions.Put(ctxA, sessionFenceKey, leaseA.fence)
	sessions.Put(ctxA, "marker", "lease-a")
	if _, _, err := sessions.Commit(ctxA); err != nil {
		t.Fatalf("lease A Commit() error = %v", err)
	}
	ctxA = withSessionLock(ctxA, token, leaseA.fence, leaseA.healthy)
	leaseA.release()

	leaseB, err := authenticator.acquireSessionLock(context.Background(), token)
	if err != nil {
		t.Fatalf("lease B acquisition error = %v", err)
	}
	defer leaseB.release()
	ctxB, err := sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("lease B Load() error = %v", err)
	}
	sessions.Put(ctxB, sessionFenceKey, leaseB.fence)
	sessions.Put(ctxB, "marker", "lease-b")
	if _, _, err := sessions.Commit(ctxB); err != nil {
		t.Fatalf("lease B Commit() error = %v", err)
	}

	sessions.Put(ctxA, "marker", "stale-a")
	if _, _, err := sessions.Commit(ctxA); err == nil {
		t.Fatal("stale lease A Commit() succeeded after lease B acquired the session")
	}
	if err := authenticator.Logout(ctxA); err == nil {
		t.Fatal("stale lease A Logout() succeeded after lease B acquired the session")
	}
	if err := sessions.RenewToken(ctxA); err == nil {
		t.Fatal("stale lease A RenewToken() succeeded after lease B acquired the session")
	}

	check, err := sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("verification Load() error = %v", err)
	}
	if got := sessions.GetString(check, "marker"); got != "lease-b" {
		t.Fatalf("stored marker = %q, want lease-b", got)
	}
}

func TestSessionMiddlewareRecoversFromEvictedSessionCookie(t *testing.T) {
	redisServer, runtime, cfg := newTestRedisRuntime(t)

	sessionCfg := config.SessionConfig{
		CookieName:       "__Host-vaultsmith_session",
		AbsoluteLifetime: time.Hour,
		IdleLifetime:     time.Minute,
		Secure:           true,
	}
	sessions := NewSessionManager(runtime.SessionStore(), sessionCfg)
	initial, err := sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	sessions.Put(initial, "marker", "before")
	token, _, err := sessions.Commit(initial)
	if err != nil {
		t.Fatalf("initial Commit() error = %v", err)
	}

	authenticator := &Authenticator{
		Config:   config.AuthConfig{Mode: config.AuthModeNative, Session: sessionCfg, Redis: cfg},
		Redis:    runtime,
		Sessions: sessions,
	}
	redisServer.FlushAll()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCfg.CookieName, Value: token})
	response := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticator.Sessions.Put(r.Context(), "marker", "recovered")
		w.WriteHeader(http.StatusNoContent)
	})

	authenticator.SessionMiddleware(handler).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d after stale cookie recovery", response.Code, http.StatusNoContent)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("replacement session cookie count = %d, want 1", len(cookies))
	}
	if cookies[0].Value == "" || cookies[0].Value == token {
		t.Fatalf("replacement session cookie = %q, want a new non-empty token", cookies[0].Value)
	}

	check, err := sessions.Load(context.Background(), cookies[0].Value)
	if err != nil {
		t.Fatalf("recovered session Load() error = %v", err)
	}
	if got := sessions.GetString(check, "marker"); got != "recovered" {
		t.Fatalf("recovered session marker = %q, want recovered", got)
	}
}

func TestSessionMiddlewareFencesCommitAfterLeaseLoss(t *testing.T) {
	redisServer := miniredis.RunT(t)
	cfg := testRedisConfig(redisServer.Addr())
	cfg.RefreshLockTTL = 120 * time.Millisecond
	cfg.RefreshLockWait = 100 * time.Millisecond
	cfg.RefreshLockRetry = 5 * time.Millisecond
	cfg.WriteTimeout = 20 * time.Millisecond
	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	sessions := NewSessionManager(memstore.New(), config.SessionConfig{
		CookieName:       "__Host-vaultsmith_session",
		AbsoluteLifetime: time.Hour,
		IdleLifetime:     time.Minute,
		Secure:           true,
	})
	initial, err := sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	sessions.Put(initial, "marker", "before")
	token, _, err := sessions.Commit(initial)
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	authenticator := &Authenticator{
		Config:   config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}, Redis: cfg},
		Redis:    runtime,
		Sessions: sessions,
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-vaultsmith_session", Value: token})
	response := httptest.NewRecorder()
	lockKey := cfg.KeyPrefix + lockKeySuffix + token
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redisServer.Del(lockKey)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			t.Error("request context was not fenced after lease loss")
		}
		authenticator.Sessions.Put(r.Context(), "marker", "after")
		w.WriteHeader(http.StatusNoContent)
	})

	authenticator.SessionMiddleware(handler).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response status = %d, want %d after lease loss", response.Code, http.StatusServiceUnavailable)
	}

	check, err := sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("re-load session: %v", err)
	}
	if got := sessions.GetString(check, "marker"); got != "before" {
		t.Fatalf("session marker = %q, want stale write fenced", got)
	}
}
