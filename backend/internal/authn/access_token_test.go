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
	tests := []struct {
		issuer string
		want   string
	}{
		{
			issuer: "https://id.example.test/realms/vaultsmith",
			want:   "https://id.example.test/realms/vaultsmith/.well-known/openid-configuration",
		},
		{
			issuer: "https://id.example.test/realms/vault%2Ftenant",
			want:   "https://id.example.test/realms/vault%2Ftenant/.well-known/openid-configuration",
		},
	}
	for _, test := range tests {
		t.Run(test.issuer, func(t *testing.T) {
			got, err := oidcDiscoveryURL(test.issuer)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("oidcDiscoveryURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOIDCDiscoveryURLRejectsIssuerQueryAndFragment(t *testing.T) {
	for _, issuer := range []string{
		"https://id.example.test/realms/vaultsmith?tenant=one",
		"https://id.example.test/realms/vaultsmith?",
		"https://id.example.test/realms/vaultsmith#fragment",
		"https://id.example.test/realms/vaultsmith#",
	} {
		t.Run(issuer, func(t *testing.T) {
			if _, err := oidcDiscoveryURL(issuer); err == nil {
				t.Fatal("oidcDiscoveryURL() accepted an issuer query or fragment")
			}
		})
	}
}

func TestValidateStrictHTTPSURLAllowsEndpointQueries(t *testing.T) {
	for _, endpoint := range []string{
		"https://id.example.test/authorize?client=vaultsmith",
		"https://id.example.test/token?audience=vaultsmith",
		"https://id.example.test/jwks?tenant=vaultsmith",
		"https://id.example.test/endpoint?",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := validateStrictHTTPSURL("endpoint", endpoint, false); err != nil {
				t.Fatalf("validateStrictHTTPSURL() error = %v", err)
			}
		})
	}
	for _, endpoint := range []string{
		"https://id.example.test/endpoint#fragment",
		"https://id.example.test/endpoint#",
		"https://id.example.test:",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := validateStrictHTTPSURL("endpoint", endpoint, false); err == nil {
				t.Fatal("validateStrictHTTPSURL() accepted an invalid endpoint")
			}
		})
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
	for _, cacheControl := range []string{"public, max-age=300", "no-store"} {
		t.Run(cacheControl, func(t *testing.T) {
			privateKey1, publicKey1 := makeRSAJWK(t, "kid-1")
			privateKey2, publicKey2 := makeRSAJWK(t, "kid-2")
			issuer := newAccessTokenIssuer(t, publicKey1, cacheControl)
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
			if got := issuer.jwksCalls.Load(); got != 2 {
				t.Fatalf("JWKS calls after successful rotation and removed-key attempt = %d, want 2", got)
			}
		})
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

func TestAccessTokenVerifierUnknownKIDThrottleRetainsUnavailableOutcome(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-known")
	issuer := newAccessTokenIssuer(t, publicKey, "no-store")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	known := signedAccessToken(t, privateKey, "kid-known", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), known); err != nil {
		t.Fatalf("Verify(known key) error = %v", err)
	}
	issuer.server.Close()

	randomKey, _ := makeRSAJWK(t, "kid-random")
	random := signedAccessToken(t, randomKey, "kid-random", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := verifier.Verify(context.Background(), random); !errors.Is(err, ErrAccessTokenKeyUnavailable) {
			t.Fatalf("Verify(random key) attempt %d error = %v, want ErrAccessTokenKeyUnavailable", attempt, err)
		}
	}
}

func TestAccessTokenVerifierUnknownKIDThrottleRetainsExpiredOutageOutcome(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-known")
	issuer := newAccessTokenIssuer(t, publicKey, "public, max-age=300")
	verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	known := signedAccessToken(t, privateKey, "kid-known", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	if _, err := verifier.Verify(context.Background(), known); err != nil {
		t.Fatalf("Verify(known key) error = %v", err)
	}
	expired := time.Now().Add(10 * time.Minute)
	verifier.now = func() time.Time { return expired }
	issuer.jwksHandler = func(w http.ResponseWriter, _ *http.Request, _ *accessTokenIssuer) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	randomKey, _ := makeRSAJWK(t, "kid-random")
	random := signedAccessToken(t, randomKey, "kid-random", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
	before := issuer.jwksCalls.Load()
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := verifier.Verify(context.Background(), random); !errors.Is(err, ErrAccessTokenKeyUnavailable) {
			t.Fatalf("Verify(random key) attempt %d error = %v, want ErrAccessTokenKeyUnavailable", attempt, err)
		}
	}
	if got := issuer.jwksCalls.Load() - before; got != 1 {
		t.Fatalf("JWKS calls after expired outage = %d, want one attempted refresh", got)
	}
}

func TestAccessTokenVerifierCanceledUnknownKIDRefreshDoesNotPoisonAvailability(t *testing.T) {
	for _, cacheControl := range []string{"public, max-age=300", "no-store"} {
		t.Run(cacheControl, func(t *testing.T) {
			privateKey, publicKey := makeRSAJWK(t, "kid-known")
			issuer := newAccessTokenIssuer(t, publicKey, cacheControl)
			issuer.jwksStarted = make(chan struct{}, 1)
			issuer.jwksBlock = make(chan struct{})
			verifier, err := NewAccessTokenVerifier(context.Background(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
			if err != nil {
				t.Fatalf("NewAccessTokenVerifier() error = %v", err)
			}

			randomKey, _ := makeRSAJWK(t, "kid-random")
			random := signedAccessToken(t, randomKey, "kid-random", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, verifyErr := verifier.Verify(ctx, random)
				result <- verifyErr
			}()

			select {
			case <-issuer.jwksStarted:
			case <-time.After(time.Second):
				t.Fatal("unknown-kid JWKS refresh did not start")
			}
			cancel()
			select {
			case verifyErr := <-result:
				if !errors.Is(verifyErr, context.Canceled) {
					t.Fatalf("Verify(canceled) error = %v, want context.Canceled", verifyErr)
				}
			case <-time.After(time.Second):
				t.Fatal("Verify(canceled) did not return promptly")
			}
			close(issuer.jwksBlock)

			known := signedAccessToken(t, privateKey, "kid-known", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
			if _, err := verifier.Verify(context.Background(), known); err != nil {
				t.Fatalf("Verify(known key after canceled refresh) error = %v", err)
			}
			otherKey, _ := makeRSAJWK(t, "kid-other")
			other := signedAccessToken(t, otherKey, "kid-other", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
			if _, err := verifier.Verify(context.Background(), other); !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("Verify(other unknown key after canceled refresh) error = %v, want ErrInvalidAccessToken", err)
			}
		})
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

	if directives.freshness != time.Minute {
		t.Fatalf("freshness = %s, want one minute; age is not a Cache-Control directive", directives.freshness)
	}
}

func TestAccessTokenVerifierIssuerTrustExpiry(t *testing.T) {
	privateKey, publicKey := makeRSAJWK(t, "kid-1")
	tests := []struct {
		name, cache, age         string
		dateAge, lifetime, grace time.Duration
		expiresLifetime          time.Duration
	}{
		{name: "short max-age", cache: "max-age=60", lifetime: time.Minute},
		{name: "unusable s-maxage falls through", cache: "s-maxage=bad, max-age=60", lifetime: time.Minute},
		{name: "unusable max-age falls through", cache: "max-age=bad", expiresLifetime: time.Minute, lifetime: time.Minute},
		{name: "unusable s-maxage uses Expires", cache: "s-maxage=bad", expiresLifetime: time.Minute, lifetime: time.Minute},
		{name: "Age header", cache: "max-age=60", age: "59", lifetime: time.Second},
		{name: "Age consumes freshness", cache: "max-age=60", age: "60"},
		{name: "large Age cannot wrap", cache: "max-age=60", age: "18446744074"},
		{name: "Date apparent age", cache: "max-age=60", dateAge: 59 * time.Second, lifetime: time.Second},
		{name: "Expires", expiresLifetime: time.Minute, lifetime: time.Minute},
		{name: "Expires with Age", expiresLifetime: time.Minute, age: "59", lifetime: time.Second},
		{name: "past Expires with large Age cannot wrap", expiresLifetime: -time.Minute, age: "18446744074"},
		{name: "headerless fallback", lifetime: time.Hour},
		{name: "freshness ceiling", cache: "max-age=86400", lifetime: 6 * time.Hour},
		{name: "zero stale", cache: "max-age=60, stale-if-error=0", lifetime: time.Minute},
		{name: "malformed stale", cache: "max-age=60, stale-if-error=invalid", lifetime: time.Minute},
		{name: "signed stale", cache: "max-age=60, stale-if-error=+30", lifetime: time.Minute},
		{name: "unclosed stale quote", cache: `max-age=60, stale-if-error="30`, lifetime: time.Minute},
		{name: "unopened stale quote", cache: `max-age=60, stale-if-error=30"`, lifetime: time.Minute},
		{name: "repeated stale quotes", cache: `max-age=60, stale-if-error=""30""`, lifetime: time.Minute},
		{name: "spaces within quoted stale", cache: `max-age=60, stale-if-error=" 30 "`, lifetime: time.Minute},
		{name: "negative stale", cache: "max-age=60, stale-if-error=-1", lifetime: time.Minute},
		{name: "oversized malformed stale", cache: "max-age=60, stale-if-error=999999999999999999999", lifetime: time.Minute},
		{name: "explicit grace", cache: "max-age=60, stale-if-error=30", lifetime: time.Minute, grace: 30 * time.Second},
		{name: "balanced quoted grace", cache: `max-age="60", stale-if-error="30"`, lifetime: time.Minute, grace: 30 * time.Second},
		{name: "zero freshness explicit grace", cache: "max-age=0, stale-if-error=30", grace: 30 * time.Second},
		{name: "Age at expiry explicit grace", cache: "max-age=60, stale-if-error=30", age: "60", grace: 30 * time.Second},
		{name: "Age beyond expiry explicit grace", cache: "max-age=60, stale-if-error=30", age: "70", lifetime: -10 * time.Second, grace: 30 * time.Second},
		{name: "grace ceiling", cache: "max-age=60, stale-if-error=86400", lifetime: time.Minute, grace: time.Hour},
		{name: "large explicit grace cannot wrap", cache: "max-age=60, stale-if-error=18446744074", lifetime: time.Minute, grace: time.Hour},
		{name: "must-revalidate", cache: "max-age=60, stale-if-error=30, must-revalidate", lifetime: time.Minute},
		{name: "proxy-revalidate", cache: "max-age=60, stale-if-error=30, proxy-revalidate", lifetime: time.Minute},
		{name: "s-maxage", cache: "s-maxage=60, max-age=300, stale-if-error=30", lifetime: time.Minute},
		{name: "no-cache", cache: "max-age=60, stale-if-error=30, no-cache"},
		{name: "zero freshness no-cache", cache: "max-age=0, stale-if-error=30, no-cache"},
		{name: "no-store", cache: "max-age=60, stale-if-error=30, no-store"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := time.Now().UTC().Truncate(time.Second)
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			// 0: current key, 1: outage, 2: key removed.
			var state atomic.Int32
			issuer := newAccessTokenIssuer(t, publicKey, test.cache)
			issuer.jwksHandler = func(w http.ResponseWriter, _ *http.Request, issuer *accessTokenIssuer) {
				if state.Load() == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				date := now().Add(-test.dateAge)
				w.Header().Set("Date", date.UTC().Format(http.TimeFormat))
				w.Header().Set("Cache-Control", test.cache)
				if test.age != "" {
					w.Header().Set("Age", test.age)
				}
				if test.expiresLifetime != 0 {
					w.Header().Set("Expires", date.Add(test.expiresLifetime).UTC().Format(http.TimeFormat))
				}
				keys := issuer.keys
				if state.Load() == 2 {
					keys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
				}
				_ = json.NewEncoder(w).Encode(keys)
			}
			verifier, err := NewAccessTokenVerifier(t.Context(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = now
			token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, map[string]any{"exp": base.Add(24 * time.Hour).Unix()})
			if _, err := verifier.Verify(t.Context(), token); err != nil {
				t.Fatalf("initial current key: %v", err)
			}
			state.Store(1)
			if test.lifetime > 0 {
				clock.Store(base.Add(test.lifetime - time.Nanosecond).UnixNano())
				if _, err := verifier.Verify(t.Context(), token); err != nil {
					t.Fatalf("before issuer expiry: %v", err)
				}
				if got := issuer.jwksCalls.Load(); got != 1 {
					t.Fatalf("fresh key fetched %d times, want 1", got)
				}
			}
			clock.Store(base.Add(max(test.lifetime, 0)).UnixNano())
			_, err = verifier.Verify(t.Context(), token)
			if test.grace > 0 {
				if err != nil {
					t.Fatalf("explicit issuer grace: %v", err)
				}
				clock.Store(base.Add(test.lifetime + test.grace).UnixNano())
				_, err = verifier.Verify(t.Context(), token)
			}
			if !errors.Is(err, ErrAccessTokenKeyUnavailable) {
				t.Fatalf("expired trust during outage: got %v, want key unavailable", err)
			}
			state.Store(0)
			// A no-store cache has no known kid; allow the existing one-minute
			// unknown-kid outage throttle to elapse before the recovery control.
			clock.Store(now().Add(time.Minute).UnixNano())
			if _, err := verifier.Verify(t.Context(), token); err != nil {
				t.Fatalf("recovered current key: %v", err)
			}
			state.Store(2)
			clock.Store(now().Add(test.lifetime).UnixNano())
			if _, err := verifier.Verify(t.Context(), token); !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("successfully removed key: got %v, want invalid token", err)
			}
			t.Logf("freshness=%s grace=%s: current-key success, expired-outage rejection, recovery success, removed-key rejection", test.lifetime, test.grace)
		})
	}
}

func TestAccessTokenVerifierRevalidatedTrustExpiry(t *testing.T) {
	for _, cache := range []string{"max-age=60", "max-age=60, stale-if-error=30"} {
		t.Run(cache, func(t *testing.T) {
			privateKey, publicKey := makeRSAJWK(t, "kid-1")
			issuer := newAccessTokenIssuer(t, publicKey, cache)
			var state atomic.Int32
			var clock atomic.Int64
			clock.Store(time.Now().UTC().Truncate(time.Second).UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			issuer.jwksHandler = func(w http.ResponseWriter, r *http.Request, issuer *accessTokenIssuer) {
				w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
				switch state.Load() {
				case 0:
					w.Header().Set("Cache-Control", cache)
					w.Header().Set("ETag", `"v1"`)
					_ = json.NewEncoder(w).Encode(issuer.keys)
				case 1, 2:
					if r.Header.Get("If-None-Match") != `"v1"` {
						t.Error("304 request missing validator")
					}
					if state.Load() == 2 {
						w.Header().Set("Cache-Control", "max-age=60")
					}
					w.WriteHeader(http.StatusNotModified)
				default:
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}
			verifier, err := NewAccessTokenVerifier(t.Context(), issuer.server.URL, issuer.server.URL, "groups", issuer.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = now
			token := signedAccessToken(t, privateKey, "kid-1", "at+jwt", issuer.server.URL, issuer.server.URL, nil)
			if _, err := verifier.Verify(t.Context(), token); err != nil {
				t.Fatal(err)
			}
			for _, step := range []int32{1, 2} {
				clock.Store(now().Add(time.Minute).UnixNano())
				state.Store(step)
				if _, err := verifier.Verify(t.Context(), token); err != nil {
					t.Fatalf("304 revalidation: %v", err)
				}
				state.Store(3)
				clock.Store(now().Add(time.Minute).UnixNano())
				_, err := verifier.Verify(t.Context(), token)
				if step == 1 && strings.Contains(cache, "stale-if-error") {
					if err != nil {
						t.Fatalf("sparse 304 lost explicit grace: %v", err)
					}
				} else if !errors.Is(err, ErrAccessTokenKeyUnavailable) {
					t.Fatalf("304 supplied implicit grace: %v", err)
				}
			}
			t.Log("conditional/sparse 304 preserved policy; replacement Cache-Control removed explicit grace")
		})
	}
}
