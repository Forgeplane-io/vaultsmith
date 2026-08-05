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
	sessionEmailVerifiedKey  = "auth.email_verified"
	sessionGroupsKey         = "auth.groups"
	sessionIssuedAtKey       = "auth.issued_at"
	sessionExpiresAtKey      = "auth.expires_at"
	sessionRefreshTokenKey   = "auth.refresh_token"
	sessionVersionKey        = "auth.version"
	sessionRefreshCheckedKey = "auth.refresh_checked_at"
	pendingStateKey          = "auth.pending_state"
)

func init() {
	gob.Register(time.Time{})
	gob.Register([]string{})
}

type Principal struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Groups        []string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

func NewSessionManager(store scs.Store, cfg config.SessionConfig) *scs.SessionManager {
	manager := scs.New()
	manager.Store = store
	manager.Lifetime = cfg.AbsoluteLifetime
	manager.IdleTimeout = cfg.IdleLifetime
	manager.HashTokenInStore = true
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
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
	}
	return manager
}

func StorePrincipal(ctx context.Context, manager *scs.SessionManager, principal Principal, refreshToken string) {
	manager.Put(ctx, sessionIssuerKey, principal.Issuer)
	manager.Put(ctx, sessionSubjectKey, principal.Subject)
	manager.Put(ctx, sessionEmailKey, principal.Email)
	manager.Put(ctx, sessionEmailVerifiedKey, principal.EmailVerified)
	groups := make([]string, len(principal.Groups))
	copy(groups, principal.Groups)
	manager.Put(ctx, sessionGroupsKey, groups)
	manager.Put(ctx, sessionIssuedAtKey, principal.IssuedAt)
	manager.Put(ctx, sessionExpiresAtKey, principal.ExpiresAt)
	if manager.GetInt64(ctx, sessionVersionKey) == 0 {
		manager.Put(ctx, sessionVersionKey, int64(1))
	}
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

	groupsValue := manager.Get(ctx, sessionGroupsKey)
	groups, ok := groupsValue.([]string)
	if !ok {
		if groupsValue != nil {
			return Principal{}, false, fmt.Errorf("malformed authentication session groups")
		}
		groups = []string{}
	}
	issuedAt, ok := manager.Get(ctx, sessionIssuedAtKey).(time.Time)
	if !ok {
		return Principal{}, false, fmt.Errorf("malformed authentication session issued time")
	}
	expiresAt, ok := manager.Get(ctx, sessionExpiresAtKey).(time.Time)
	if !ok || expiresAt.IsZero() {
		return Principal{}, false, fmt.Errorf("malformed authentication session expiry")
	}
	verified, ok := manager.Get(ctx, sessionEmailVerifiedKey).(bool)
	if !ok {
		return Principal{}, false, fmt.Errorf("malformed authentication session email state")
	}

	principalGroups := make([]string, len(groups))
	copy(principalGroups, groups)
	return Principal{
		Issuer:        issuer,
		Subject:       subject,
		Email:         manager.GetString(ctx, sessionEmailKey),
		EmailVerified: verified,
		Groups:        principalGroups,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
	}, true, nil
}

func RefreshTokenFromSession(ctx context.Context, manager *scs.SessionManager) string {
	return manager.GetString(ctx, sessionRefreshTokenKey)
}

func ClearPrincipal(ctx context.Context, manager *scs.SessionManager) {
	for _, key := range []string{
		sessionIssuerKey,
		sessionSubjectKey,
		sessionEmailKey,
		sessionEmailVerifiedKey,
		sessionGroupsKey,
		sessionIssuedAtKey,
		sessionExpiresAtKey,
		sessionRefreshTokenKey,
		sessionVersionKey,
		sessionRefreshCheckedKey,
		pendingStateKey,
	} {
		manager.Remove(ctx, key)
	}
}

func principalFromClaims(issuer string, claims map[string]any, groupsClaim string, issuedAt, expiresAt time.Time) (Principal, error) {
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
		Issuer:        issuer,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
		Groups:        groups,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
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
	case []string:
		groups := make([]string, len(typed))
		for index, group := range typed {
			if strings.TrimSpace(group) == "" {
				return nil, fmt.Errorf("empty group")
			}
			groups[index] = group
		}
		return groups, nil
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
