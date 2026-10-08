package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/go-jose/go-jose/v4"
)

// This issuer performs a real code/PKCE exchange and serves signed ID tokens
// over TLS. Its refresh response is controlled; it is not a production IdP.
type nativeRefreshIssuer struct {
	server *httptest.Server
	mu     sync.Mutex
	nonce  string
	pkce   string
	expiry time.Time
	mode   string
	used   []string
}

func newNativeRefreshIssuer(t *testing.T, mode string) *nativeRefreshIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeRefreshIssuer{mode: mode}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks",
			"authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "synthetic", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		q := r.URL.Query()
		if q.Get("client_id") != "browser-client" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
			http.Error(w, "invalid fixture authorization", http.StatusBadRequest)
			return
		}
		f.nonce, f.pkce = q.Get("nonce"), q.Get("code_challenge")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=synthetic-code&state="+url.QueryEscape(q.Get("state")), http.StatusSeeOther)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims := map[string]any{"iss": f.server.URL, "sub": "subject", "aud": "browser-client", "groups": []string{"admins"}, "exp": time.Now().Add(time.Hour).Unix()}
		response := map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "refresh_token": "rotated-refresh", "expires_in": 3600}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "synthetic-code" || f.pkce != base64.RawURLEncoding.EncodeToString(challenge[:]) || f.nonce == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Match the existing authn refresh fixture: claims expire inside
			// the refresh skew. Tests wait for this exact deadline, not a cap.
			f.expiry = time.Now().Add(5 * time.Second).Truncate(time.Second)
			claims["exp"], claims["nonce"] = f.expiry.Unix(), f.nonce
			response["refresh_token"] = "login-refresh"
		case "refresh_token":
			f.used = append(f.used, r.Form.Get("refresh_token"))
			switch f.mode {
			case "oauth-only":
				_ = json.NewEncoder(w).Encode(response)
				return
			case "permanent", "transient":
				code := "invalid_grant"
				if f.mode == "transient" {
					code = "temporarily_unavailable"
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
				return
			case "changed-groups":
				claims["groups"] = []string{"removed-grant"}
			case "fresh-id-token":
				// Retain the current groups with newly verified claim expiry.
			case "short-id-token":
				// Stay inside the one-minute refresh skew, but beyond the
				// five-second session fixture, for the recent-refresh shortcut.
				claims["exp"] = time.Now().Add(30 * time.Second).Unix()
			case "missing-groups":
				delete(claims, "groups")
			case "malformed-groups":
				claims["groups"] = []any{"admins", 42}
			case "different-subject":
				claims["sub"] = "other-subject"
			case "different-issuer":
				claims["iss"] = "https://other.example.test"
			case "wrong-audience":
				claims["aud"] = "other-client"
			case "expired-id-token":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			default:
				http.Error(w, "unknown fixture refresh mode", http.StatusInternalServerError)
				return
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Error("fixture claims could not be encoded")
			return
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Error("fixture claims could not be signed")
			return
		}
		raw, err := signed.CompactSerialize()
		if err != nil {
			t.Error("fixture token could not be serialized")
			return
		}
		response["id_token"] = raw
		_ = json.NewEncoder(w).Encode(response)
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

type nativeRefreshFlow struct {
	server *httptest.Server
	client *http.Client
	auth   *authn.Authenticator
	redis  *miniredis.Miniredis
	issuer *nativeRefreshIssuer
	exec   *recordingExecutor
	csrf   string
}

func newNativeRefreshFlow(t *testing.T, mode string, absoluteOnly bool) *nativeRefreshFlow {
	t.Helper()
	f := &nativeRefreshFlow{issuer: newNativeRefreshIssuer(t, mode), redis: miniredis.RunT(t), exec: &recordingExecutor{}}
	redisConfig := config.RedisConfig{Address: f.redis.Addr(), KeyPrefix: "native-refresh:", ConnectTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, PoolSize: 4, RefreshLockTTL: 500 * time.Millisecond, RefreshLockWait: 100 * time.Millisecond, RefreshLockRetry: 10 * time.Millisecond, ProviderTimeout: 100 * time.Millisecond}
	runtime, err := authn.NewRedisRuntime(redisConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	caFile := filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(nil)
	t.Cleanup(f.server.Close)
	base := "https://" + f.server.Listener.Addr().String()
	cfg := config.AuthConfig{
		Mode: config.AuthModeNative, Redis: redisConfig,
		OIDC:    config.OIDCConfig{IssuerURL: f.issuer.server.URL, CAFile: caFile, ClientID: "browser-client", ClientSecret: "synthetic-client-secret", PublicBaseURL: base, RedirectURL: base + "/auth/callback", GroupsClaim: "groups", Scopes: []string{"openid"}},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", AbsoluteLifetime: time.Hour, IdleLifetime: time.Minute, Secure: true, SameSite: http.SameSiteLaxMode},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
	}
	if absoluteOnly {
		cfg.Session.IdleLifetime = 0
	}
	f.auth, err = authn.NewAuthenticator(t.Context(), cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authz.LoadPolicy(writeNativePolicy(t), []string{"dev", "prod", "read"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatal(err)
	}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, f.exec, Dependencies{Auth: f.auth, Authorizer: authorizer, AuthConfig: cfg})
	f.server.Config.Handler = WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: f.auth})
	f.server.StartTLS()
	f.client = f.server.Client()
	f.client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}

func (f *nativeRefreshFlow) request(t *testing.T, method, path string) (int, []byte, http.Header) {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"vaultText":"synthetic-vault-text"}`)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, body)
	if err != nil {
		t.Fatal("fixture request could not be constructed")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", f.server.URL)
		req.Header.Set(csrfHeaderName, f.csrf)
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("fixture HTTP request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("fixture HTTP response failed")
	}
	return response.StatusCode, data, response.Header
}

func (f *nativeRefreshFlow) login(t *testing.T) {
	t.Helper()
	status, body, _ := f.request(t, http.MethodGet, "/api/v1/session")
	var session sessionResponse
	if status != http.StatusOK || json.Unmarshal(body, &session) != nil || session.Authenticated || session.CSRFToken == "" {
		t.Fatal("unauthenticated CSRF bootstrap failed")
	}
	f.csrf = session.CSRFToken
	status, _, headers := f.request(t, http.MethodGet, "/auth/login?return_to=%2F")
	if status != http.StatusSeeOther {
		t.Fatalf("login status=%d", status)
	}
	client := f.issuer.server.Client()
	client.CheckRedirect = f.client.CheckRedirect
	response, err := client.Get(headers.Get("Location"))
	if err != nil {
		t.Fatal("fixture authorization failed")
	}
	_ = response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusSeeOther {
		t.Fatal("fixture authorization did not return a callback")
	}
	status, _, _ = f.request(t, http.MethodGet, callback.RequestURI())
	if status != http.StatusSeeOther {
		t.Fatalf("verified login callback status=%d", status)
	}
}

func TestNativeHTTPRefreshClaimFreshness(t *testing.T) {
	for _, scenario := range []struct {
		name string
		mode string
		want int
	}{
		{"oauth-only-expiry", "oauth-only", http.StatusOK},
		{"changed-groups", "changed-groups", http.StatusForbidden},
		{"missing-groups", "missing-groups", http.StatusForbidden},
		{"malformed-groups", "malformed-groups", http.StatusUnauthorized},
		{"different-subject", "different-subject", http.StatusUnauthorized},
		{"different-issuer", "different-issuer", http.StatusUnauthorized},
		{"wrong-audience", "wrong-audience", http.StatusUnauthorized},
		{"expired-id-token", "expired-id-token", http.StatusUnauthorized},
		{"permanent-failure", "permanent", http.StatusUnauthorized},
		{"transient-failure", "transient", http.StatusServiceUnavailable},
		{"legacy-renewed-session", "oauth-only", http.StatusUnauthorized},
		{"absolute-lifetime", "oauth-only", http.StatusOK},
		{"idle-lifetime", "oauth-only", http.StatusOK},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newNativeRefreshFlow(t, scenario.mode, scenario.name == "absolute-lifetime")
			statuses := []int{}
			deniedExecutor := false
			t.Cleanup(func() {
				receipt := map[string]any{"fixture": "synthetic-tls-code-pkce-native-http", "scenario": scenario.name, "statuses": statuses, "denied_executor_called": deniedExecutor, "passed": !t.Failed()}
				data, err := json.MarshalIndent(receipt, "", "  ")
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.WriteFile(filepath.Join(t.ArtifactDir(), "receipt.json"), data, 0o600); err != nil {
					t.Error(err)
				}
			})
			f.login(t)
			if scenario.name == "legacy-renewed-session" {
				base, _ := url.Parse(f.server.URL)
				var token string
				for _, cookie := range f.client.Jar.Cookies(base) {
					if cookie.Name == f.auth.Config.Session.CookieName {
						token = cookie.Value
					}
				}
				hash := sha256.Sum256([]byte(token))
				key := f.auth.Config.Redis.KeyPrefix + "session:" + base64.RawURLEncoding.EncodeToString(hash[:])
				raw, err := f.redis.Get(key)
				if err != nil || token == "" {
					t.Fatal("legacy fixture session unavailable")
				}
				deadline, values, err := f.auth.Sessions.Codec.Decode([]byte(raw))
				if err != nil {
					t.Fatal("legacy fixture session could not be decoded")
				}
				binding, _ := json.Marshal([3]string{f.auth.Config.OIDC.IssuerURL, f.auth.Config.OIDC.ClientID, f.auth.Config.OIDC.PublicBaseURL})
				values["auth.binding"] = fmt.Sprintf("v1:%x", sha256.Sum256(binding))
				values["auth.expires_at"] = time.Now().Add(time.Hour)
				data, err := f.auth.Sessions.Codec.Encode(deadline, values)
				if err != nil {
					t.Fatal("legacy fixture session could not be encoded")
				}
				// Replace disposable fixture data with the previous format;
				// the next request must use the normal fenced lifecycle.
				ttl := f.redis.TTL(key)
				if err := f.redis.Set(key, string(data)); err != nil {
					t.Fatal("legacy fixture write failed")
				}
				f.redis.SetTTL(key, ttl)
			}
			status, body, _ := f.request(t, http.MethodPost, "/api/v1/profiles/dev/decrypt")
			statuses = append(statuses, status)
			if status != scenario.want {
				t.Fatalf("protected decrypt status=%d want=%d", status, scenario.want)
			}
			if status != http.StatusOK {
				deniedExecutor = f.exec.called
				if deniedExecutor || strings.Contains(string(body), "plaintext") {
					t.Fatal("denied decrypt executed or returned decrypted output")
				}
			} else if !f.exec.called {
				t.Fatal("authorized control did not execute decrypt")
			}
			if scenario.name == "oauth-only-expiry" || scenario.name == "absolute-lifetime" || scenario.name == "idle-lifetime" {
				if scenario.name == "oauth-only-expiry" {
					f.issuer.mu.Lock()
					expiry := f.issuer.expiry
					f.issuer.mu.Unlock()
					time.Sleep(time.Until(expiry))
				} else if scenario.name == "absolute-lifetime" {
					f.redis.FastForward(f.auth.Config.Session.AbsoluteLifetime)
				} else {
					f.redis.FastForward(f.auth.Config.Session.IdleLifetime)
				}
				f.exec.called = false
				status, body, _ = f.request(t, http.MethodPost, "/api/v1/profiles/dev/decrypt")
				statuses = append(statuses, status)
				deniedExecutor = f.exec.called
				if status != http.StatusUnauthorized || deniedExecutor || strings.Contains(string(body), "plaintext") {
					t.Fatalf("expired decrypt status=%d executor_called=%t", status, deniedExecutor)
				}
			}
			if scenario.name == "oauth-only-expiry" {
				f.issuer.mu.Lock()
				rotated := len(f.issuer.used) == 2 && f.issuer.used[0] == "login-refresh" && f.issuer.used[1] == "rotated-refresh"
				f.issuer.mu.Unlock()
				if !rotated {
					t.Fatal("OAuth-only flow did not use the rotated refresh token at claim expiry")
				}
			}
			if scenario.name == "transient-failure" {
				f.issuer.mu.Lock()
				f.issuer.mode = "oauth-only"
				f.issuer.mu.Unlock()
			}
			status, body, _ = f.request(t, http.MethodGet, "/api/v1/session")
			var session sessionResponse
			if status != http.StatusOK || json.Unmarshal(body, &session) != nil {
				t.Fatal("session outcome could not be checked")
			}
			wantAuthenticated := scenario.want == http.StatusForbidden || scenario.want == http.StatusServiceUnavailable
			if session.Authenticated != wantAuthenticated {
				t.Fatalf("session authenticated=%t want=%t", session.Authenticated, wantAuthenticated)
			}
		})
	}
}

// Delay only a successful session-store call's return, not Redis itself:
// the real lock heartbeat and fenced logout must remain available.
type delayedNativeRefreshStore struct {
	scs.Store
	deadline                time.Time
	delayFind               bool
	useCommitExpiry         bool
	expiringRedis           *miniredis.Miniredis
	keyPrefix               string
	once                    sync.Once
	completedBeforeDeadline atomic.Bool
	expiredWithOwnedLease   atomic.Bool
}

func (s *delayedNativeRefreshStore) Find(token string) ([]byte, bool, error) {
	data, found, err := s.Store.Find(token)
	if err == nil && found && s.delayFind {
		s.waitForDeadline(token, s.deadline)
	}
	return data, found, err
}

func (s *delayedNativeRefreshStore) Commit(token string, data []byte, expiry time.Time) error {
	if err := s.Store.Commit(token, data, expiry); err != nil {
		return err
	}
	if !s.delayFind {
		deadline := s.deadline
		if s.useCommitExpiry {
			deadline = expiry
		}
		s.waitForDeadline(token, deadline)
	}
	return nil
}

func (s *delayedNativeRefreshStore) waitForDeadline(token string, deadline time.Time) {
	s.once.Do(func() {
		s.completedBeforeDeadline.Store(time.Now().Before(deadline))
		time.Sleep(time.Until(deadline))
		if s.expiringRedis != nil {
			// Miniredis TTLs do not elapse automatically. Expire the two
			// persisted keys without removing the live, heartbeating lease.
			session := s.expiringRedis.Del(s.keyPrefix + "session:" + token)
			fence := s.expiringRedis.Del(s.keyPrefix + "fence:" + token)
			s.expiredWithOwnedLease.Store(session && fence && s.expiringRedis.Exists(s.keyPrefix+"lock:"+token))
		}
	})
}

func (s *delayedNativeRefreshStore) DeleteCtx(ctx context.Context, token string) error {
	return s.Store.(interface {
		DeleteCtx(context.Context, string) error
	}).DeleteCtx(ctx, token)
}

func TestNativeHTTPRefreshChecksDeadlinesAfterCommit(t *testing.T) {
	for _, boundary := range []string{"claims", "session", "idle"} {
		t.Run(boundary, func(t *testing.T) {
			status, deniedExecutor, committedBeforeDeadline := 0, false, false
			expiredWithOwnedLease := false
			t.Cleanup(func() {
				receipt := map[string]any{"fixture": "synthetic-tls-code-pkce-native-http", "scenario": "successful-commit-" + boundary + "-expiry", "status": status, "denied_executor_called": deniedExecutor, "successful_commit_before_deadline": committedBeforeDeadline, "expired_session_and_fence_with_active_lease": expiredWithOwnedLease, "passed": !t.Failed()}
				data, err := json.MarshalIndent(receipt, "", "  ")
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.WriteFile(filepath.Join(t.ArtifactDir(), "receipt.json"), data, 0o600); err != nil {
					t.Error(err)
				}
			})
			mode := "oauth-only"
			if boundary != "claims" {
				mode = "fresh-id-token"
			}
			f := newNativeRefreshFlow(t, mode, boundary != "idle")
			if boundary == "session" {
				// Use the existing short claim fixture's lifetime for the session;
				// the refreshed ID token remains valid beyond this deadline.
				f.auth.Sessions.Lifetime = 5 * time.Second
				f.auth.Config.Session.AbsoluteLifetime = f.auth.Sessions.Lifetime
			}
			if boundary == "idle" {
				// The same short fixture duration, with a later absolute deadline.
				f.auth.Sessions.IdleTimeout = 5 * time.Second
				f.auth.Config.Session.IdleLifetime = f.auth.Sessions.IdleTimeout
			}
			f.login(t)
			base, _ := url.Parse(f.server.URL)
			var token string
			for _, cookie := range f.client.Jar.Cookies(base) {
				if cookie.Name == f.auth.Config.Session.CookieName {
					token = cookie.Value
				}
			}
			ctx, err := f.auth.Sessions.Load(t.Context(), token)
			if err != nil || token == "" {
				t.Fatal("delayed-commit fixture session unavailable")
			}
			principal, found, err := authn.PrincipalFromSession(ctx, f.auth.Sessions)
			if err != nil || !found {
				t.Fatal("delayed-commit fixture principal unavailable")
			}
			deadline := principal.ExpiresAt
			if boundary == "session" {
				deadline = f.auth.Sessions.Deadline(ctx)
			}
			store := &delayedNativeRefreshStore{Store: f.auth.Sessions.Store, deadline: deadline, useCommitExpiry: boundary == "idle"}
			if boundary != "claims" {
				store.expiringRedis, store.keyPrefix = f.redis, f.auth.Config.Redis.KeyPrefix
			}
			f.auth.Sessions.Store = store
			status, body, _ := f.request(t, http.MethodPost, "/api/v1/profiles/dev/decrypt")
			deniedExecutor, committedBeforeDeadline = f.exec.called, store.completedBeforeDeadline.Load()
			expiredWithOwnedLease = store.expiredWithOwnedLease.Load()
			if !committedBeforeDeadline {
				t.Fatal("fixture did not complete a successful commit before the deadline")
			}
			if boundary != "claims" && !expiredWithOwnedLease {
				t.Fatal("fixture did not expire session and fence while retaining the lease")
			}
			if status != http.StatusUnauthorized || deniedExecutor || strings.Contains(string(body), "plaintext") {
				t.Fatalf("post-commit expiry status=%d executor_called=%t", status, deniedExecutor)
			}
			sessionStatus, body, _ := f.request(t, http.MethodGet, "/api/v1/session")
			var session sessionResponse
			if sessionStatus != http.StatusOK || json.Unmarshal(body, &session) != nil || session.Authenticated {
				t.Fatal("post-commit expiry did not require a new login")
			}
		})
	}
}

func TestNativeHTTPChecksSessionDeadlineAfterLoad(t *testing.T) {
	for _, shortcut := range []string{"fresh", "retry"} {
		t.Run(shortcut, func(t *testing.T) {
			status, deniedExecutor, readBeforeDeadline := 0, false, false
			t.Cleanup(func() {
				receipt := map[string]any{"fixture": "synthetic-tls-code-pkce-native-http", "scenario": "successful-load-" + shortcut + "-session-expiry", "status": status, "denied_executor_called": deniedExecutor, "successful_read_before_deadline": readBeforeDeadline, "passed": !t.Failed()}
				data, err := json.MarshalIndent(receipt, "", "  ")
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.WriteFile(filepath.Join(t.ArtifactDir(), "receipt.json"), data, 0o600); err != nil {
					t.Error(err)
				}
			})
			mode := "fresh-id-token"
			if shortcut == "retry" {
				mode = "short-id-token"
			}
			f := newNativeRefreshFlow(t, mode, true)
			f.auth.Sessions.Lifetime = 5 * time.Second
			f.auth.Config.Session.AbsoluteLifetime = f.auth.Sessions.Lifetime
			f.login(t)
			controlStatus, _, _ := f.request(t, http.MethodPost, "/api/v1/profiles/dev/decrypt")
			if controlStatus != http.StatusOK || !f.exec.called {
				t.Fatal("delayed-load fixture could not establish refreshed claims")
			}
			base, _ := url.Parse(f.server.URL)
			var token string
			for _, cookie := range f.client.Jar.Cookies(base) {
				if cookie.Name == f.auth.Config.Session.CookieName {
					token = cookie.Value
				}
			}
			ctx, err := f.auth.Sessions.Load(t.Context(), token)
			if err != nil || token == "" {
				t.Fatal("delayed-load fixture session unavailable")
			}
			deadline := f.auth.Sessions.Deadline(ctx)
			principal, found, err := authn.PrincipalFromSession(ctx, f.auth.Sessions)
			if err != nil || !found || !principal.ExpiresAt.After(deadline) {
				t.Fatal("fixture claims do not outlive the absolute session deadline")
			}
			store := &delayedNativeRefreshStore{Store: f.auth.Sessions.Store, deadline: deadline, delayFind: true}
			f.auth.Sessions.Store = store
			f.exec.called = false
			status, body, _ := f.request(t, http.MethodPost, "/api/v1/profiles/dev/decrypt")
			deniedExecutor, readBeforeDeadline = f.exec.called, store.completedBeforeDeadline.Load()
			if !readBeforeDeadline {
				t.Fatal("fixture did not retrieve a live session before its deadline")
			}
			if status != http.StatusUnauthorized || deniedExecutor || strings.Contains(string(body), "plaintext") {
				t.Fatalf("post-load expiry status=%d executor_called=%t", status, deniedExecutor)
			}
			sessionStatus, body, _ := f.request(t, http.MethodGet, "/api/v1/session")
			var session sessionResponse
			if sessionStatus != http.StatusOK || json.Unmarshal(body, &session) != nil || session.Authenticated {
				t.Fatal("post-load expiry did not require a new login")
			}
		})
	}
}
