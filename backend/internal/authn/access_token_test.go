package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type accessTokenIssuer struct {
	server         *httptest.Server
	keys           jose.JSONWebKeySet
	cache          string
	discoveryExtra map[string]any
	jwksCalls      atomic.Int32
	jwksStarted    chan struct{}
	jwksBlock      chan struct{}
	jwksHandler    func(http.ResponseWriter, *http.Request, *accessTokenIssuer)
}

type advancingRoundTripper struct {
	now *time.Time
}

func (r advancingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	*r.now = r.now.Add(2 * time.Second)
	return nil, errors.New("issuer unavailable")
}

func newAccessTokenIssuer(t *testing.T, key jose.JSONWebKey, cacheControl string) *accessTokenIssuer {
	t.Helper()
	issuer := &accessTokenIssuer{keys: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}, cache: cacheControl}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		document := map[string]any{
			"issuer":                 issuer.server.URL,
			"jwks_uri":               issuer.server.URL + "/jwks",
			"authorization_endpoint": issuer.server.URL + "/authorize",
			"token_endpoint":         issuer.server.URL + "/token",
		}
		for key, value := range issuer.discoveryExtra {
			document[key] = value
		}
		_ = json.NewEncoder(w).Encode(document)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		issuer.jwksCalls.Add(1)
		if issuer.jwksHandler != nil {
			issuer.jwksHandler(w, r, issuer)
			return
		}
		if issuer.jwksBlock != nil {
			select {
			case issuer.jwksStarted <- struct{}{}:
			default:
			}
			<-issuer.jwksBlock
		}
		w.Header().Set("Cache-Control", issuer.cache)
		w.Header().Set("ETag", `"test-etag"`)
		_ = json.NewEncoder(w).Encode(issuer.keys)
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func makeRSAJWK(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
}

func signedAccessToken(t *testing.T, key *rsa.PrivateKey, kid, typ, issuer, audience string, patch map[string]any) string {
	t.Helper()
	now := time.Now().UTC()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	options.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{
		Issuer:    issuer,
		Subject:   "subject",
		Audience:  jwt.Audience{audience},
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ID:        "synthetic-jti",
	}
	extra := map[string]any{
		"client_id": "vaultsmith-ci",
		"scope":     "vaultsmith.profile.read vaultsmith.encrypt",
		"groups":    []string{"operators"},
	}
	for key, value := range patch {
		extra[key] = value
	}
	raw, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOIDCDiscoveryURLPreservesIssuerPath(t *testing.T) {
	got, err := oidcDiscoveryURL("https://id.example.test/realms/vaultsmith")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://id.example.test/realms/vaultsmith/.well-known/openid-configuration"
	if got != want {
		t.Fatalf("oidcDiscoveryURL() = %q, want %q", got, want)
	}
}

func TestAccessTokenVerifierAcceptsRFC9068JWT(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "application/AT+JWT", issuer.server.URL, issuer.server.URL, nil)

	actor, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if actor.Kind() != caller.KindBearer || actor.Issuer() != issuer.server.URL || actor.Subject() != "subject" {
		t.Fatalf("actor = %#v", actor)
	}
	if got := actor.Scopes(); strings.Join(got, " ") != "vaultsmith.encrypt vaultsmith.profile.read" {
		t.Fatalf("scopes = %#v", got)
	}
	if groups := actor.Groups(); len(groups) != 1 || groups[0] != "operators" {
		t.Fatalf("groups = %#v", groups)
	}
}

func TestAccessTokenVerifierRejectsDuplicateScopes(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, map[string]any{"scope": "vaultsmith.encrypt vaultsmith.encrypt"})
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify() error = %v, want ErrInvalidAccessToken", err)
	}
}
func TestAccessTokenVerifierDiscoveryAllowsOptionalAndExtensionMembers(t *testing.T) {
	_, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	issuer.discoveryExtra = map[string]any{
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "client_credentials"},
		"x-vaultsmith-extension":   map[string]any{"enabled": true},
	}

	if _, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client()); err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v, want optional discovery metadata accepted", err)
	}
}

func TestFetchStrictDiscoveryRejectsTrailingJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token"}{}`)
	}))
	t.Cleanup(server.Close)

	if _, err := fetchStrictDiscovery(context.Background(), server.Client(), server.URL); err == nil {
		t.Fatal("fetchStrictDiscovery() accepted trailing JSON")
	}
}

func TestFetchStrictDiscoveryRejectsRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	t.Cleanup(source.Close)

	if _, err := fetchStrictDiscovery(context.Background(), source.Client(), source.URL); err == nil {
		t.Fatal("fetchStrictDiscovery() followed a redirect")
	}
}

func TestAccessTokenVerifierRejectsInvalidTypeAudienceScopeAndGroups(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	tests := []struct {
		name     string
		typ      string
		audience string
		patch    map[string]any
	}{
		{name: "type parameter", typ: "application/at+jwt; charset=utf-8", audience: issuer.server.URL},
		{name: "wrong audience", typ: "at+jwt", audience: "https://other.example"},
		{name: "scope array", typ: "at+jwt", audience: issuer.server.URL, patch: map[string]any{"scope": []string{"vaultsmith.encrypt"}}},
		{name: "empty scope", typ: "at+jwt", audience: issuer.server.URL, patch: map[string]any{"scope": ""}},
		{name: "scope empty element", typ: "at+jwt", audience: issuer.server.URL, patch: map[string]any{"scope": "vaultsmith.encrypt  vaultsmith.decrypt"}},
		{name: "malformed groups", typ: "at+jwt", audience: issuer.server.URL, patch: map[string]any{"groups": []any{"operators", ""}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signedAccessToken(t, privateKey, "kid-1", test.typ, issuer.server.URL, test.audience, test.patch)
			if _, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatal("Verify() unexpectedly succeeded")
			}
		})
	}
}

func TestAccessTokenVerifierRefreshesUnknownKIDAndDoesNotAcceptRemovedKeys(t *testing.T) {
	privateKey1, publicKey1 := makeRSAJWK(t, "kid-1")
	privateKey2, publicKey2 := makeRSAJWK(t, "kid-2")
	issuer := newAccessTokenIssuer(t, publicKey1, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token1 := signedAccessToken(t, privateKey1, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), token1); err != nil {
		t.Fatalf("Verify(old key) error = %v", err)
	}

	issuer.keys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey2}}
	token2 := signedAccessToken(t, privateKey2, "kid-2", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), token2); err != nil {
		t.Fatalf("Verify(new key) error = %v", err)
	}
	if _, err := verifier.Verify(context.Background(), token1); err == nil {
		t.Fatal("Verify(removed key) unexpectedly succeeded")
	}
}

func TestAccessTokenVerifierUnknownKIDRefreshUsesSingleflight(t *testing.T) {
	privateKey1, publicKey1 := makeRSAJWK(t, "kid-1")
	privateKey2, publicKey2 := makeRSAJWK(t, "kid-2")
	issuer := newAccessTokenIssuer(t, publicKey1, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token1 := signedAccessToken(t, privateKey1, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), token1); err != nil {
		t.Fatalf("Verify(old key) error = %v", err)
	}

	issuer.keys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey2}}
	issuer.jwksStarted = make(chan struct{}, 1)
	issuer.jwksBlock = make(chan struct{})
	token2 := signedAccessToken(t, privateKey2, "kid-2", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	before := issuer.jwksCalls.Load()

	const waiters = 8
	start := make(chan struct{})
	errs := make(chan error, waiters)
	var wg sync.WaitGroup
	for range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, verifyErr := verifier.Verify(context.Background(), token2)
			errs <- verifyErr
		}()
	}
	close(start)
	select {
	case <-issuer.jwksStarted:
	case <-time.After(time.Second):
		t.Fatal("unknown-kid JWKS refresh did not start")
	}
	close(issuer.jwksBlock)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Verify(new key) error = %v, want all waiters to share refreshed keys", err)
		}
	}
	if got := issuer.jwksCalls.Load() - before; got != 1 {
		t.Fatalf("JWKS refresh calls = %d, want 1", got)
	}
}

func TestAccessTokenVerifierUnknownKIDThrottleAppliesDuringRevalidation(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-known")
	randomKey, _ := makeRSAJWK(t, "kid-random")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=0")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	known := signedAccessToken(t, privateKey, "kid-known", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), known); err != nil {
		t.Fatalf("Verify(known key) error = %v", err)
	}

	random1 := signedAccessToken(t, randomKey, "kid-random-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	random2 := signedAccessToken(t, randomKey, "kid-random-2", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	before := issuer.jwksCalls.Load()
	if _, err := verifier.Verify(context.Background(), random1); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify(random kid 1) error = %v, want ErrInvalidAccessToken", err)
	}
	if _, err := verifier.Verify(context.Background(), random2); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify(random kid 2) error = %v, want ErrInvalidAccessToken", err)
	}
	if got := issuer.jwksCalls.Load() - before; got != 1 {
		t.Fatalf("JWKS calls for sequential random kids = %d, want 1 during revalidation", got)
	}
}

func TestAccessTokenVerifierNoStoreInvalidatesRetainedKeys(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "no-store")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify(no-store triggering request) error = %v", err)
	}
	issuer.server.Close()
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify(no-store cached key) unexpectedly succeeded after issuer outage")
	}
}

func TestAccessTokenVerifierStaleCutoffUsesPostRefreshTime(t *testing.T) {
	current := time.Unix(1_700_000_000, 0)
	cache := &jwksCache{
		keys:       jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "kid-1"}}},
		haveKeys:   true,
		expiry:     current.Add(-time.Minute),
		staleUntil: current.Add(time.Second),
	}
	verifier := &AccessTokenVerifier{
		client:  &http.Client{Transport: advancingRoundTripper{now: &current}},
		jwksURL: "https://issuer.example.test/jwks",
		now:     func() time.Time { return current },
	}

	_, err := cache.keysForKID(context.Background(), verifier, "kid-1")
	if !errors.Is(err, ErrAccessTokenKeyUnavailable) {
		t.Fatalf("keysForKID() error = %v, want ErrAccessTokenKeyUnavailable after refresh crosses stale cutoff", err)
	}
}

func TestAccessTokenVerifierNoStoreIsNotSharedWithWaiters(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "no-store")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)

	const callers = 8
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, verifyErr := verifier.Verify(context.Background(), token)
			errs <- verifyErr
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Verify(no-store) error = %v", err)
		}
	}
	if got := issuer.jwksCalls.Load(); got != callers {
		t.Fatalf("JWKS calls = %d, want %d independent no-store fetches", got, callers)
	}
}

func TestAccessTokenVerifierSparse304RetainsRevalidationDirectives(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "unused")
	issuer.jwksHandler = func(w http.ResponseWriter, r *http.Request, issuer *accessTokenIssuer) {
		if issuer.jwksCalls.Load() == 1 {
			w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
			w.Header().Set("ETag", `"v1"`)
			_ = json.NewEncoder(w).Encode(issuer.keys)
			return
		}
		if r.Header.Get("If-None-Match") != `"v1"` {
			t.Errorf("If-None-Match = %q, want v1 validator", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := verifier.Verify(context.Background(), token); err != nil {
			t.Fatalf("Verify() attempt %d error = %v", attempt+1, err)
		}
	}
	if got := issuer.jwksCalls.Load(); got != 3 {
		t.Fatalf("JWKS calls = %d, want revalidation on every verification", got)
	}
}

func TestAccessTokenVerifierRejectsTrailingJWKSJSON(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	issuer.jwksHandler = func(w http.ResponseWriter, _ *http.Request, issuer *accessTokenIssuer) {
		encoded, err := json.Marshal(issuer.keys)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(append(encoded, []byte(`{}`)...))
	}
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() accepted a JWKS response with trailing JSON")
	}
}

func TestJWKSCacheIgnoresAgeCacheControlDirective(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	directives := parseCacheDirectives(http.Header{
		"Cache-Control": []string{"public, max-age=60, age=59"},
	}, now)

	if directives.freshness != jwksMinFreshness {
		t.Fatalf("freshness = %s, want %s for positive freshness below the five-minute floor", directives.freshness, jwksMinFreshness)
	}
}
