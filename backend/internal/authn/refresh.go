package authn

import (
	"context"
	"errors"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"golang.org/x/oauth2"
)

const (
	refreshSkew        = time.Minute
	refreshRetryWindow = 30 * time.Second
)

func (a *Authenticator) AuthenticatedPrincipal(ctx context.Context) (Principal, bool, error) {
	if a.Config.Mode == config.AuthModeOff {
		return Principal{}, false, ErrAuthenticationDisabled
	}
	principal, found, err := PrincipalFromSession(ctx, a.Sessions)
	if err != nil {
		if destroyErr := a.destroySession(ctx); destroyErr != nil {
			return Principal{}, false, destroyErr
		}
		return Principal{}, false, ErrNotAuthenticated
	}
	if !found {
		return Principal{}, false, nil
	}
	now := time.Now()
	if principal.ExpiresAt.After(now.Add(refreshSkew)) {
		return principal, true, nil
	}
	refreshToken := RefreshTokenFromSession(ctx, a.Sessions)
	if refreshToken == "" {
		return Principal{}, false, ErrRefreshRequired
	}
	lastChecked := a.Sessions.GetTime(ctx, sessionRefreshCheckedKey)
	if principal.ExpiresAt.After(now) && !lastChecked.IsZero() && now.Before(lastChecked.Add(refreshRetryWindow)) {
		return principal, true, nil
	}
	return a.refreshSession(ctx)
}

func (a *Authenticator) refreshSession(ctx context.Context) (Principal, bool, error) {
	if a.Redis == nil || a.Sessions == nil {
		return Principal{}, false, ErrTemporaryUnavailable
	}
	sessionToken := a.Sessions.Token(ctx)
	if sessionToken == "" {
		return Principal{}, false, ErrNotAuthenticated
	}
	lock, err := a.acquireSessionLock(ctx, sessionToken)
	if err != nil {
		return Principal{}, false, err
	}
	defer lock.release()
	if lock.fence != "" {
		a.Sessions.Put(lock.ctx, sessionFenceKey, lock.fence)
	}
	ctx = withSessionLock(lock.ctx, sessionToken, lock.fence, lock.healthy)

	freshCtx, err := a.Sessions.Load(contextWithoutSession(ctx), sessionToken)
	if err != nil {
		return Principal{}, false, ErrTemporaryUnavailable
	}
	freshPrincipal, freshFound, err := PrincipalFromSession(freshCtx, a.Sessions)
	if err != nil {
		return Principal{}, false, ErrTemporaryUnavailable
	}
	if !freshFound {
		return Principal{}, false, ErrNotAuthenticated
	}
	freshRefreshToken := RefreshTokenFromSession(freshCtx, a.Sessions)
	now := time.Now()
	if freshPrincipal.ExpiresAt.After(now.Add(refreshSkew)) {
		if err := a.syncSession(ctx, freshCtx, freshPrincipal, freshRefreshToken, 0, false); err != nil {
			return Principal{}, false, err
		}
		return freshPrincipal, true, nil
	}
	lastChecked := a.Sessions.GetTime(freshCtx, sessionRefreshCheckedKey)
	if !lastChecked.IsZero() && freshPrincipal.ExpiresAt.After(now) && now.Before(lastChecked.Add(refreshRetryWindow)) {
		if err := a.syncSession(ctx, freshCtx, freshPrincipal, freshRefreshToken, 0, false); err != nil {
			return Principal{}, false, err
		}
		return freshPrincipal, true, nil
	}
	if freshRefreshToken == "" {
		return Principal{}, false, ErrRefreshRequired
	}

	exchangeCtx, cancel := a.oidcTimeoutContext(ctx)
	defer cancel()
	exchange := a.refreshExchange
	if exchange == nil {
		exchange = a.exchangeRefreshToken
	}
	rotated, err := exchange(exchangeCtx, freshRefreshToken)
	if err != nil {
		if isPermanentRefreshFailure(err) {
			if destroyErr := a.destroySession(ctx); destroyErr != nil {
				return Principal{}, false, destroyErr
			}
			return Principal{}, false, ErrNotAuthenticated
		}
		return Principal{}, false, ErrTemporaryUnavailable
	}
	if rotated == nil {
		return Principal{}, false, ErrTemporaryUnavailable
	}

	refreshedPrincipal := freshPrincipal
	rawIDToken, hasIDToken := rotated.Extra("id_token").(string)
	if hasIDToken && rawIDToken != "" {
		refreshedPrincipal, err = a.verifyRefreshedIDToken(ctx, rawIDToken, freshPrincipal)
		if err != nil {
			if destroyErr := a.destroySession(ctx); destroyErr != nil {
				return Principal{}, false, destroyErr
			}
			return Principal{}, false, ErrNotAuthenticated
		}
	} else {
		refreshedPrincipal.ExpiresAt = refreshedSessionExpiry(a.Sessions.Deadline(freshCtx), rotated.Expiry)
		if !refreshedPrincipal.ExpiresAt.After(now) {
			if destroyErr := a.destroySession(ctx); destroyErr != nil {
				return Principal{}, false, destroyErr
			}
			return Principal{}, false, ErrNotAuthenticated
		}
	}

	newRefreshToken := rotated.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = freshRefreshToken
	}
	version := a.Sessions.GetInt64(freshCtx, sessionVersionKey) + 1
	if version <= 0 {
		version = 1
	}
	if err := a.syncSession(ctx, freshCtx, refreshedPrincipal, newRefreshToken, version, true); err != nil {
		return Principal{}, false, err
	}
	return refreshedPrincipal, true, nil
}

func (a *Authenticator) syncSession(ctx, freshCtx context.Context, principal Principal, refreshToken string, version int64, markRefresh bool) error {
	StorePrincipal(ctx, a.Sessions, principal, refreshToken)
	if version <= 0 {
		version = a.Sessions.GetInt64(freshCtx, sessionVersionKey)
		if version <= 0 {
			version = 1
		}
	}
	a.Sessions.Put(ctx, sessionVersionKey, version)
	if markRefresh {
		a.Sessions.Put(ctx, sessionRefreshCheckedKey, time.Now())
	}
	if _, _, err := a.Sessions.Commit(ctx); err != nil {
		return ErrTemporaryUnavailable
	}
	return nil
}

func (a *Authenticator) exchangeRefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	source := a.OAuth2.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	return source.Token()
}

func (a *Authenticator) verifyRefreshedIDToken(ctx context.Context, rawIDToken string, previous Principal) (Principal, error) {
	if a.Verifier == nil {
		return Principal{}, ErrInvalidCallback
	}
	verifyCtx, cancel := a.oidcTimeoutContext(ctx)
	defer cancel()
	idToken, err := a.Verifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		return Principal{}, ErrInvalidCallback
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Principal{}, ErrInvalidCallback
	}
	principal, err := principalFromClaims(a.Config.OIDC.IssuerURL, claims, a.Config.OIDC.GroupsClaim, idToken.IssuedAt, idToken.Expiry)
	if err != nil || principal.Issuer != previous.Issuer || principal.Subject != previous.Subject {
		return Principal{}, ErrInvalidCallback
	}
	return principal, nil
}

func isPermanentRefreshFailure(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	return errors.As(err, &retrieveErr) && retrieveErr.ErrorCode == "invalid_grant"
}

func (a *Authenticator) destroySession(ctx context.Context) error {
	if err := a.Logout(ctx); err != nil {
		return ErrTemporaryUnavailable
	}
	return nil
}

func refreshedSessionExpiry(deadline, tokenExpiry time.Time) time.Time {
	expiry := deadline
	if expiry.IsZero() || (!tokenExpiry.IsZero() && tokenExpiry.Before(expiry)) {
		expiry = tokenExpiry
	}
	return expiry
}
