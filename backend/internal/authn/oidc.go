package authn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"golang.org/x/oauth2"
)

var ErrAuthenticationDisabled = fmt.Errorf("authentication is disabled")

type Authenticator struct {
	Config   config.AuthConfig
	Redis    *RedisRuntime
	Sessions *scs.SessionManager
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
	OAuth2   oauth2.Config

	oidcClient      *http.Client
	refreshExchange func(context.Context, string) (*oauth2.Token, error)
}

func newOIDCHTTPClient(caFile string) (*http.Client, error) {
	if strings.TrimSpace(caFile) == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("OIDC CA file unavailable")
	}
	pool, poolErr := x509.SystemCertPool()
	if poolErr != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("OIDC CA file contains no certificates")
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("OIDC HTTP transport unavailable")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = pool
	return &http.Client{Transport: transport}, nil
}

func (a *Authenticator) oidcContext(ctx context.Context) context.Context {
	if a.oidcClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, a.oidcClient)
}

func NewAuthenticator(ctx context.Context, cfg config.AuthConfig, runtime *RedisRuntime) (*Authenticator, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	service := &Authenticator{
		Config: cfg,
		Redis:  runtime,
	}
	if cfg.Mode == config.AuthModeOff {
		service.Sessions = NewSessionManager(memstore.New(), cfg.Session)
		return service, nil
	}
	if cfg.Mode != config.AuthModeNative {
		return nil, fmt.Errorf("unsupported authentication mode")
	}
	if runtime == nil {
		return nil, fmt.Errorf("native authentication requires Redis")
	}
	oidcClient, err := newOIDCHTTPClient(cfg.OIDC.CAFile)
	if err != nil {
		return nil, fmt.Errorf("OIDC trust configuration failed")
	}
	service.oidcClient = oidcClient
	provider, err := oidc.NewProvider(service.oidcContext(ctx), cfg.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed")
	}
	service.Provider = provider
	service.Verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	service.OAuth2 = oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       append([]string(nil), cfg.OIDC.Scopes...),
	}
	service.Sessions = NewSessionManager(runtime.SessionStore(), cfg.Session)
	return service, nil
}

func (a *Authenticator) BeginLogin(ctx context.Context, returnTo string) (string, error) {
	if a.Config.Mode != config.AuthModeNative || a.Redis == nil {
		return "", ErrAuthenticationDisabled
	}
	returnTo, err := safeReturnTo(returnTo)
	if err != nil {
		return "", err
	}
	state, err := randomURLToken(32)
	if err != nil {
		return "", fmt.Errorf("generate login state")
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return "", fmt.Errorf("generate login nonce")
	}
	verifier, err := randomURLToken(32)
	if err != nil {
		return "", fmt.Errorf("generate PKCE verifier")
	}

	a.Sessions.Put(ctx, pendingStateKey, state)
	preAuthSession, _, err := a.Sessions.Commit(ctx)
	if err != nil {
		return "", fmt.Errorf("create pre-authentication session")
	}
	transaction := LoginTransaction{
		State:          state,
		Nonce:          nonce,
		PKCEVerifier:   verifier,
		PreAuthSession: preAuthSession,
		ReturnTo:       returnTo,
		ExpiresAt:      time.Now().Add(loginTransactionLifetime),
	}
	if err := a.Redis.SaveLoginTransaction(ctx, transaction); err != nil {
		_ = a.Logout(ctx)
		return "", ErrTemporaryUnavailable
	}
	return a.OAuth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

func (a *Authenticator) CompleteLogin(ctx context.Context, state, code string) (string, Principal, error) {
	if a.Config.Mode != config.AuthModeNative || a.Redis == nil {
		return "", Principal{}, ErrAuthenticationDisabled
	}
	if state == "" || code == "" {
		return "", Principal{}, ErrInvalidCallback
	}
	transaction, found, err := a.Redis.ConsumeLoginTransaction(ctx, state)
	if err != nil {
		return "", Principal{}, ErrTemporaryUnavailable
	}
	if !found || a.Sessions.Token(ctx) == "" || a.Sessions.Token(ctx) != transaction.PreAuthSession {
		return "", Principal{}, ErrInvalidCallback
	}

	exchangeCtx, cancel := context.WithTimeout(a.oidcContext(ctx), a.Config.Redis.ProviderTimeout)
	defer cancel()
	token, err := a.OAuth2.Exchange(exchangeCtx, code, oauth2.VerifierOption(transaction.PKCEVerifier))
	if err != nil {
		return "", Principal{}, ErrInvalidCallback
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", Principal{}, ErrInvalidCallback
	}
	principal, err := a.verifyIDToken(ctx, rawIDToken, transaction.Nonce)
	if err != nil {
		return "", Principal{}, ErrInvalidCallback
	}
	if err := a.Sessions.RenewToken(ctx); err != nil {
		return "", Principal{}, ErrTemporaryUnavailable
	}
	rebindSessionLock(ctx, a.Sessions.Token(ctx))
	if fence := sessionLockFence(ctx); fence != "" {
		if err := a.Redis.ActivateSessionFence(ctx, a.Sessions.Token(ctx), fence, a.Config.Session.AbsoluteLifetime); err != nil {
			return "", Principal{}, ErrTemporaryUnavailable
		}
	}
	StorePrincipal(ctx, a.Sessions, principal, token.RefreshToken)
	a.Sessions.Remove(ctx, pendingStateKey)
	if token.RefreshToken == "" {
		a.Sessions.SetDeadline(ctx, refreshedSessionExpiry(a.Sessions.Deadline(ctx), principal.ExpiresAt))
	}
	return transaction.ReturnTo, principal, nil
}

func (a *Authenticator) verifyIDToken(ctx context.Context, rawIDToken, expectedNonce string) (Principal, error) {
	if a.Verifier == nil || expectedNonce == "" {
		return Principal{}, ErrInvalidCallback
	}
	idToken, err := a.Verifier.Verify(a.oidcContext(ctx), rawIDToken)
	if err != nil || idToken.Nonce != expectedNonce {
		return Principal{}, ErrInvalidCallback
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Principal{}, ErrInvalidCallback
	}
	return principalFromClaims(a.Config.OIDC.IssuerURL, claims, a.Config.OIDC.GroupsClaim, idToken.IssuedAt, idToken.Expiry)
}

func randomURLToken(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func safeReturnTo(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\\r\n\x00") || strings.HasPrefix(value, "//") {
		return "", fmt.Errorf("return path must be an internal URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Scheme != "" || !strings.HasPrefix(parsed.Path, "/") {
		return "", fmt.Errorf("return path must be an internal URL")
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || strings.HasPrefix(decodedPath, "//") {
		return "", fmt.Errorf("return path must be an internal URL")
	}
	return value, nil
}
