package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func newRefreshService(t *testing.T, exchange func(context.Context, string) (*oauth2.Token, error)) (*Authenticator, string) {
	t.Helper()
	server := miniredis.RunT(t)
	redisConfig := testRedisConfig(server.Addr())
	redisConfig.RefreshLockTTL = 500 * time.Millisecond
	redisConfig.RefreshLockWait = 250 * time.Millisecond
	redisConfig.RefreshLockRetry = 10 * time.Millisecond
	runtime := newRedisRuntimeForTest(t, redisConfig)
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
	ctx := mustLoadSession(t, service.Sessions, "")
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
		t.Fatalf("Sessions.Commit() error = %v", err)
	}
	return service, token
}

func TestAuthenticatedPrincipalRotatesRefreshTokenAndExtendsSessionExpiryWithoutIDToken(t *testing.T) {
	service, token := newRefreshService(t, func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
		if refreshToken != "old-refresh" {
			t.Fatalf("refresh token = %q, want old-refresh", refreshToken)
		}
		return &oauth2.Token{RefreshToken: "new-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	})

	ctx := mustLoadSession(t, service.Sessions, token)
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
	service, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		close(started)
		<-release
		return &oauth2.Token{RefreshToken: "rotated", Expiry: time.Now().Add(time.Hour)}, nil
	})

	refreshCtx := mustLoadSession(t, service.Sessions, token)
	logoutCtx := mustLoadSession(t, service.Sessions, token)

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
	fresh := mustLoadSession(t, service.Sessions, token)
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
		t.Fatalf("session after serialized logout = (found=%t, err=%v), want absent", found, err)
	}
}

func TestAuthenticatedPrincipalSerializesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	service, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return &oauth2.Token{RefreshToken: "rotated"}, nil
	})

	contexts := make([]context.Context, 2)
	for index := range contexts {
		contexts[index] = mustLoadSession(t, service.Sessions, token)
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
	service, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	})

	ctx := mustLoadSession(t, service.Sessions, token)
	_, _, err := service.AuthenticatedPrincipal(ctx)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("AuthenticatedPrincipal() error = %v, want ErrNotAuthenticated", err)
	}
	fresh := mustLoadSession(t, service.Sessions, token)
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
		t.Fatalf("destroyed session state = (found=%t, err=%v), want absent", found, err)
	}
}

func TestAuthenticatedPrincipalPreservesSessionOnTransientRefreshFailure(t *testing.T) {
	service, token := newRefreshService(t, func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, errors.New("provider unavailable")
	})

	ctx := mustLoadSession(t, service.Sessions, token)
	_, _, err := service.AuthenticatedPrincipal(ctx)
	if !errors.Is(err, ErrTemporaryUnavailable) {
		t.Fatalf("AuthenticatedPrincipal() error = %v, want ErrTemporaryUnavailable", err)
	}
	fresh := mustLoadSession(t, service.Sessions, token)
	if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || !found {
		t.Fatalf("preserved session state = (found=%t, err=%v), want present", found, err)
	}
}

func TestAuthenticatedPrincipalRefreshesExpiredPrincipalWhenRefreshTokenExists(t *testing.T) {
	service, token := newRefreshService(t, func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
		if refreshToken != "old-refresh" {
			t.Fatalf("refresh token = %q, want old-refresh", refreshToken)
		}
		return &oauth2.Token{RefreshToken: "new-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	})

	ctx := mustLoadSession(t, service.Sessions, token)
	service.Sessions.Put(ctx, sessionExpiresAtKey, time.Now().Add(-time.Minute))
	if _, _, err := service.Sessions.Commit(ctx); err != nil {
		t.Fatalf("Sessions.Commit() error = %v", err)
	}

	principal, found, err := service.AuthenticatedPrincipal(ctx)
	if err != nil || !found {
		t.Fatalf("AuthenticatedPrincipal() = (%+v, %t, %v), want refreshed principal", principal, found, err)
	}
	if !principal.ExpiresAt.After(time.Now()) {
		t.Fatalf("refreshed principal expiry = %s, want future expiry", principal.ExpiresAt)
	}
}

func TestAuthenticatedPrincipalRejectsExpiredPrincipalWithoutRefreshToken(t *testing.T) {
	service, token := newRefreshService(t, func(context.Context, string) (*oauth2.Token, error) {
		t.Fatal("refresh exchange called without a refresh token")
		return nil, nil
	})

	ctx := mustLoadSession(t, service.Sessions, token)
	StorePrincipal(ctx, service.Sessions, Principal{
		Issuer:    "https://issuer.example",
		Subject:   "user-123",
		IssuedAt:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}, "")
	if _, _, err := service.Sessions.Commit(ctx); err != nil {
		t.Fatalf("Sessions.Commit() error = %v", err)
	}

	_, _, err := service.AuthenticatedPrincipal(ctx)
	if err != ErrRefreshRequired {
		t.Fatalf("AuthenticatedPrincipal() error = %v, want ErrRefreshRequired", err)
	}
}

func TestRefreshExchangeUsesConfiguredOIDCClientContext(t *testing.T) {
	service, token := newRefreshService(t, nil)

	service.OAuth2 = oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: "https://issuer.example.test/token"}}
	var calls atomic.Int32
	service.oidcClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"access","token_type":"Bearer","refresh_token":"new-refresh","expires_in":3600}`)),
			Request:    req,
		}, nil
	})}
	service.refreshExchange = service.exchangeRefreshToken

	ctx := mustLoadSession(t, service.Sessions, token)
	if _, _, err := service.AuthenticatedPrincipal(ctx); err != nil {
		t.Fatalf("AuthenticatedPrincipal() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("configured OIDC HTTP client calls = %d, want 1", got)
	}
}

func signedIDTokenFixture(t *testing.T, issuer, keyID, clientID string) (string, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": "user-123",
		"aud": clientID,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("json.Marshal(claims) error = %v", err)
	}
	rawIDToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("signer.Sign() error = %v", err)
	}
	compactIDToken, err := rawIDToken.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() error = %v", err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	if err != nil {
		t.Fatalf("json.Marshal(jwks) error = %v", err)
	}
	return compactIDToken, jwks
}

func TestRefreshedIDTokenVerificationWaitIsBounded(t *testing.T) {
	const issuer = "https://issuer.example.test"
	const keyID = "stalled-jwks-key"
	const clientID = "stalled-jwks-client"
	compactIDToken, _ := signedIDTokenFixture(t, issuer, keyID, clientID)

	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	var startOnce sync.Once
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		startOnce.Do(func() { close(started) })
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-release:
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
	})}
	provider := (&oidc.ProviderConfig{IssuerURL: issuer, JWKSURL: issuer + "/keys"}).NewProvider(oidc.ClientContext(context.Background(), client))
	timeout := 20 * time.Millisecond
	service := &Authenticator{
		Config:     config.AuthConfig{OIDC: config.OIDCConfig{IssuerURL: issuer, ClientID: clientID}, Redis: config.RedisConfig{ProviderTimeout: timeout}},
		oidcClient: client,
		Verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
	}

	done := make(chan error, 1)
	go func() {
		_, err := service.verifyRefreshedIDToken(context.Background(), compactIDToken, Principal{Issuer: issuer, Subject: "user-123"})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("JWKS request did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidCallback) {
			t.Fatalf("verifyRefreshedIDToken() error = %v, want ErrInvalidCallback", err)
		}
	case <-time.After(10 * timeout):
		t.Fatalf("verifyRefreshedIDToken() did not honor provider timeout %s", timeout)
	}
}

func TestRefreshedIDTokenVerificationUsesProviderOIDCClient(t *testing.T) {
	const issuer = "https://issuer.example.test"
	const keyID = "refresh-test-key"
	const clientID = "refresh-test-client"
	compactIDToken, jwks := signedIDTokenFixture(t, issuer, keyID, clientID)

	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.String() != "https://issuer.example.test/keys" {
			t.Fatalf("JWKS request URL = %q", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(jwks))),
			Request:    req,
		}, nil
	})}
	provider := (&oidc.ProviderConfig{IssuerURL: issuer, JWKSURL: "https://issuer.example.test/keys"}).NewProvider(oidc.ClientContext(context.Background(), client))
	service := &Authenticator{
		Config:     config.AuthConfig{OIDC: config.OIDCConfig{IssuerURL: issuer, ClientID: clientID}, Redis: config.RedisConfig{ProviderTimeout: time.Second}},
		oidcClient: client,
		Verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
	}

	principal, err := service.verifyRefreshedIDToken(context.Background(), compactIDToken, Principal{Issuer: issuer, Subject: "user-123"})
	if err != nil {
		t.Fatalf("verifyRefreshedIDToken() error = %v (configured client calls=%d)", err, calls.Load())
	}
	if principal.Subject != "user-123" {
		t.Fatalf("verified principal subject = %q, want user-123", principal.Subject)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("configured OIDC HTTP client calls = %d, want 1", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestRefreshedSessionExpiryIsBoundedByAbsoluteLifetime(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	got := refreshedSessionExpiry(deadline, time.Now().Add(time.Hour))
	if got.After(deadline) {
		t.Fatalf("refreshed expiry = %s, exceeds absolute deadline %s", got, deadline)
	}
}
