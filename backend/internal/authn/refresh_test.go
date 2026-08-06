package authn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"golang.org/x/oauth2"
)

func newRefreshService(t *testing.T, exchange func(context.Context, string) (*oauth2.Token, error)) (*Authenticator, *RedisRuntime, string) {
	t.Helper()
	server := miniredis.RunT(t)
	redisConfig := testRedisConfig(server.Addr())
	redisConfig.RefreshLockTTL = 500 * time.Millisecond
	redisConfig.RefreshLockWait = 250 * time.Millisecond
	redisConfig.RefreshLockRetry = 10 * time.Millisecond
	runtime, err := NewRedisRuntime(redisConfig)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	sessionConfig := config.SessionConfig{
		CookieName:       "__Host-vaultsmith_session",
		AbsoluteLifetime: 8 * time.Hour,
		IdleLifetime:     30 * time.Minute,
		Secure:           true,
		SameSite:         1,
	}
	service := &Authenticator{
		Config:          config.AuthConfig{Mode: config.AuthModeNative, Session: sessionConfig, Redis: redisConfig},
		Redis:           runtime,
		Sessions:        NewSessionManager(runtime.SessionStore(), sessionConfig),
		refreshExchange: exchange,
	}
	ctx, err := service.Sessions.Load(context.Background(), "")
	if err != nil {
		runtime.Close()
		t.Fatalf("Sessions.Load() error = %v", err)
	}
	principal := Principal{
		Issuer:    "https://issuer.example",
		Subject:   "user-123",
		Groups:    []string{"vault-readers"},
		IssuedAt:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(5 * time.Second),
	}
	StorePrincipal(ctx, service.Sessions, principal, "old-refresh")
	token, _, err := service.Sessions.Commit(ctx)
	if err != nil {
		runtime.Close()
		t.Fatalf("Sessions.Commit() error = %v", err)
	}
	return service, runtime, token
}

func TestAuthenticatedPrincipalRotatesRefreshTokenAndExtendsSessionExpiryWithoutIDToken(t *testing.T) {
	service, runtime, token := newRefreshService(t, func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
		if refreshToken != "old-refresh" {
			t.Fatalf("refresh token = %q, want old-refresh", refreshToken)
		}
		return &oauth2.Token{RefreshToken: "new-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	})
	defer runtime.Close()

	ctx, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("Sessions.Load() error = %v", err)
	}
	principal, found, err := service.AuthenticatedPrincipal(ctx)
	if err != nil || !found {
		t.Fatalf("AuthenticatedPrincipal() = (%+v, %t, %v)", principal, found, err)
	}
	if principal.Subject != "user-123" || !principal.ExpiresAt.After(time.Now().Add(30*time.Minute)) {
		t.Fatalf("unexpected principal after refresh: %+v", principal)
	}
	if got := RefreshTokenFromSession(ctx, service.Sessions); got != "new-refresh" {
		t.Fatalf("stored refresh token = %q, want new-refresh", got)
	}
}

func TestLogoutSerializesWithInFlightRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	service, runtime, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		close(started)
		<-release
		return &oauth2.Token{RefreshToken: "rotated", Expiry: time.Now().Add(time.Hour)}, nil
	})
	defer runtime.Close()

	refreshCtx, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("refresh Sessions.Load() error = %v", err)
	}
	logoutCtx, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("logout Sessions.Load() error = %v", err)
	}

	refreshErr := make(chan error, 1)
	go func() {
		_, _, err := service.AuthenticatedPrincipal(refreshCtx)
		refreshErr <- err
	}()
	<-started

	logoutErr := make(chan error, 1)
	go func() { logoutErr <- service.Logout(logoutCtx) }()
	time.Sleep(20 * time.Millisecond)
	close(release)

	if err := <-refreshErr; err != nil {
		t.Fatalf("refresh error = %v", err)
	}
	if err := <-logoutErr; err != nil {
		t.Fatalf("logout error = %v", err)
	}
	fresh, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("fresh Sessions.Load() error = %v", err)
	}
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
		t.Fatalf("session after serialized logout = (found=%t, err=%v), want absent", found, err)
	}
}

func TestAuthenticatedPrincipalSerializesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	service, runtime, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return &oauth2.Token{RefreshToken: "rotated"}, nil
	})
	defer runtime.Close()

	contexts := make([]context.Context, 2)
	for index := range contexts {
		ctx, err := service.Sessions.Load(context.Background(), token)
		if err != nil {
			t.Fatalf("Sessions.Load() error = %v", err)
		}
		contexts[index] = ctx
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(contexts))
	for _, ctx := range contexts {
		wg.Add(1)
		go func(ctx context.Context) {
			defer wg.Done()
			_, _, err := service.AuthenticatedPrincipal(ctx)
			errs <- err
		}(ctx)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AuthenticatedPrincipal() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("refresh exchange calls = %d, want 1", got)
	}
}

func TestAuthenticatedPrincipalDestroysSessionOnInvalidGrant(t *testing.T) {
	service, runtime, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	})
	defer runtime.Close()

	ctx, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("Sessions.Load() error = %v", err)
	}
	_, _, err = service.AuthenticatedPrincipal(ctx)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("AuthenticatedPrincipal() error = %v, want ErrNotAuthenticated", err)
	}
	fresh, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("fresh Sessions.Load() error = %v", err)
	}
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
		t.Fatalf("destroyed session state = (found=%t, err=%v), want absent", found, err)
	}
}

func TestAuthenticatedPrincipalPreservesSessionOnTransientRefreshFailure(t *testing.T) {
	service, runtime, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, errors.New("provider unavailable")
	})
	defer runtime.Close()

	ctx, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("Sessions.Load() error = %v", err)
	}
	_, _, err = service.AuthenticatedPrincipal(ctx)
	if !errors.Is(err, ErrTemporaryUnavailable) {
		t.Fatalf("AuthenticatedPrincipal() error = %v, want ErrTemporaryUnavailable", err)
	}
	fresh, err := service.Sessions.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("fresh Sessions.Load() error = %v", err)
	}
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || !found {
		t.Fatalf("preserved session state = (found=%t, err=%v), want present", found, err)
	}
}

type fixedDeadlineSessions struct {
	deadline time.Time
}

func (s fixedDeadlineSessions) Deadline(context.Context) time.Time {
	return s.deadline
}

func TestRefreshedSessionExpiryIsBoundedByAbsoluteLifetime(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	got := refreshedSessionExpiry(fixedDeadlineSessions{deadline: deadline}, context.Background(), time.Now().Add(time.Hour))
	if got.After(deadline) {
		t.Fatalf("refreshed expiry = %s, exceeds absolute deadline %s", got, deadline)
	}
}
