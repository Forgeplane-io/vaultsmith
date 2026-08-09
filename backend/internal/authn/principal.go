package authn

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

var (
	errSessionStore         = errors.New("session store unavailable")
	ErrNotAuthenticated     = errors.New("not authenticated")
	ErrInvalidCallback      = errors.New("invalid authentication callback")
	ErrTemporaryUnavailable = errors.New("authentication temporarily unavailable")
	ErrRefreshRequired      = errors.New("authentication refresh required")
)

const (
	sessionIssuerKey         = "auth.issuer"
	sessionSubjectKey        = "auth.subject"
	sessionEmailKey          = "auth.email"
	sessionGroupsKey         = "auth.groups"
	sessionExpiresAtKey      = "auth.expires_at"
	sessionRefreshTokenKey   = "auth.refresh_token"
	sessionRefreshCheckedKey = "auth.refresh_checked_at"
	sessionFenceKey          = "auth.session_fence"
	pendingStateKey          = "auth.pending_state"
)

func init() {
	gob.Register(time.Time{})
	gob.Register([]string{})
}

type Principal struct {
	Issuer    string
	Subject   string
	Email     string
	Groups    []string
	ExpiresAt time.Time
}

func NewSessionManager(store scs.Store, cfg config.SessionConfig) *scs.SessionManager {
	manager := scs.New()
	manager.Store = store
	manager.Lifetime = cfg.AbsoluteLifetime
	manager.IdleTimeout = cfg.IdleLifetime
	manager.HashTokenInStore = true
	if binder, ok := store.(interface{ SetCodec(scs.Codec) }); ok {
		binder.SetCodec(manager.Codec)
	}
	if binder, ok := store.(interface{ SetHashTokenInStore(bool) }); ok {
		binder.SetHashTokenInStore(manager.HashTokenInStore)
	}
	manager.Cookie = scs.SessionCookie{
		Name:     cfg.CookieName,
		Domain:   "",
		HttpOnly: true,
		Path:     "/",
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
		Persist:  true,
	}
	manager.ErrorFunc = func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{\"error\":{\"code\":\"temporarily_unavailable\",\"message\":\"service is temporarily unavailable\"}}"))
	}
	return manager
}

func StorePrincipal(ctx context.Context, manager *scs.SessionManager, principal Principal, refreshToken string) {
	manager.Put(ctx, sessionIssuerKey, principal.Issuer)
	manager.Put(ctx, sessionSubjectKey, principal.Subject)
	manager.Put(ctx, sessionEmailKey, principal.Email)
	groups := make([]string, len(principal.Groups))
	copy(groups, principal.Groups)
	manager.Put(ctx, sessionGroupsKey, groups)
	manager.Put(ctx, sessionExpiresAtKey, principal.ExpiresAt)
	if refreshToken == "" {
		manager.Remove(ctx, sessionRefreshTokenKey)
	} else {
		manager.Put(ctx, sessionRefreshTokenKey, refreshToken)
	}
}

func PrincipalFromSession(ctx context.Context, manager *scs.SessionManager) (Principal, bool, error) {
	issuer := manager.GetString(ctx, sessionIssuerKey)
	subject := manager.GetString(ctx, sessionSubjectKey)
	if issuer == "" && subject == "" {
		return Principal{}, false, nil
	}
	if issuer == "" || subject == "" {
		return Principal{}, false, fmt.Errorf("malformed authentication session")
	}

	groups, ok := manager.Get(ctx, sessionGroupsKey).([]string)
	if !ok {
		return Principal{}, false, fmt.Errorf("malformed authentication session groups")
	}
	expiresAt, ok := manager.Get(ctx, sessionExpiresAtKey).(time.Time)
	if !ok || expiresAt.IsZero() {
		return Principal{}, false, fmt.Errorf("malformed authentication session expiry")
	}
	principalGroups := make([]string, len(groups))
	copy(principalGroups, groups)
	return Principal{
		Issuer:    issuer,
		Subject:   subject,
		Email:     manager.GetString(ctx, sessionEmailKey),
		Groups:    principalGroups,
		ExpiresAt: expiresAt,
	}, true, nil
}

func RefreshTokenFromSession(ctx context.Context, manager *scs.SessionManager) string {
	return manager.GetString(ctx, sessionRefreshTokenKey)
}

func principalFromClaims(issuer string, claims map[string]any, groupsClaim string, expiresAt time.Time) (Principal, error) {
	if strings.TrimSpace(issuer) == "" {
		return Principal{}, fmt.Errorf("issuer claim is required")
	}
	subject, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(subject) == "" {
		return Principal{}, fmt.Errorf("subject claim is required")
	}
	groupsValue, ok := claimPathValue(claims, groupsClaim)
	groups := []string{}
	if ok {
		var err error
		groups, err = strictStringArray(groupsValue)
		if err != nil {
			return Principal{}, fmt.Errorf("groups claim must be a string array")
		}
	}

	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	if !emailVerified {
		email = ""
	}
	return Principal{
		Issuer:    issuer,
		Subject:   subject,
		Email:     email,
		Groups:    groups,
		ExpiresAt: expiresAt,
	}, nil
}

func claimPathValue(claims map[string]any, path string) (any, bool) {
	var current any = claims
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func strictStringArray(value any) ([]string, error) {
	switch typed := value.(type) {
	case []any:
		groups := make([]string, len(typed))
		for index, item := range typed {
			group, ok := item.(string)
			if !ok || strings.TrimSpace(group) == "" {
				return nil, fmt.Errorf("group is not a string")
			}
			groups[index] = group
		}
		return groups, nil
	default:
		return nil, fmt.Errorf("groups is not an array")
	}
}
