package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

func TestSessionManagerUsesOpaqueHostCookieDefaults(t *testing.T) {
	manager := NewSessionManager(memstore.New(), config.SessionConfig{
		CookieName:       "__Host-vaultsmith_session",
		AbsoluteLifetime: 8 * time.Hour,
		IdleLifetime:     30 * time.Minute,
		Secure:           true,
		SameSite:         http.SameSiteLaxMode,
	})
	if !manager.HashTokenInStore {
		t.Fatal("HashTokenInStore = false, want true")
	}
	if manager.Cookie.Name != "__Host-vaultsmith_session" || manager.Cookie.Domain != "" || manager.Cookie.Path != "/" {
		t.Fatalf("unexpected cookie configuration: %+v", manager.Cookie)
	}
	if !manager.Cookie.HttpOnly || !manager.Cookie.Secure || manager.Cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("insecure cookie configuration: %+v", manager.Cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, err := manager.Load(req.Context(), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	manager.Put(ctx, sessionSubjectKey, "subject")
	if _, _, err := manager.Commit(ctx); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	response := httptest.NewRecorder()
	manager.WriteSessionCookie(ctx, response, manager.Token(ctx), time.Now().Add(time.Hour))
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Domain != "" || cookie.Path != "/" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected Set-Cookie attributes: %+v", cookie)
	}
}

func TestSessionManagerLoadAndSaveDoesNotExposeStoreErrors(t *testing.T) {
	manager := NewSessionManager(errorStore{}, config.SessionConfig{
		CookieName:       "__Host-vaultsmith_session",
		AbsoluteLifetime: time.Hour,
		IdleLifetime:     time.Minute,
		Secure:           true,
		SameSite:         http.SameSiteLaxMode,
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-vaultsmith_session", Value: "token"})
	manager.LoadAndSave(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("LoadAndSave() status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("LoadAndSave() body is not JSON: %v", err)
	}
	if body.Error.Code != "temporarily_unavailable" {
		t.Fatalf("LoadAndSave() error code = %q", body.Error.Code)
	}
}

func TestPrincipalFromSessionTreatsNilGroupsAsEmpty(t *testing.T) {
	manager := NewSessionManager(memstore.New(), config.SessionConfig{
		AbsoluteLifetime: time.Hour,
		IdleLifetime:     time.Minute,
	})
	ctx, err := manager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	StorePrincipal(ctx, manager, Principal{
		Issuer:        "issuer",
		Subject:       "subject",
		EmailVerified: true,
		ExpiresAt:     time.Now().Add(time.Hour),
	}, "")
	manager.Put(ctx, sessionGroupsKey, nil)

	principal, found, err := PrincipalFromSession(ctx, manager)
	if err != nil || !found {
		t.Fatalf("PrincipalFromSession() = (%+v, %t, %v)", principal, found, err)
	}
	if principal.Groups == nil || len(principal.Groups) != 0 {
		t.Fatalf("groups = %#v, want non-nil empty group set", principal.Groups)
	}
}

type errorStore struct{}

func (errorStore) Delete(string) error                    { return errSessionStore }
func (errorStore) Find(string) ([]byte, bool, error)      { return nil, false, errSessionStore }
func (errorStore) Commit(string, []byte, time.Time) error { return errSessionStore }
