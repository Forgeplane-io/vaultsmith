package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/sync/singleflight"
)

const (
	accessTokenHTTPTimeout = 5 * time.Second
	jwksDefaultFreshness   = time.Hour
	jwksMinFreshness       = 5 * time.Minute
	jwksMaxFreshness       = 6 * time.Hour
	jwksMaxStaleUse        = time.Hour
	accessTokenSkew        = time.Minute
	maxScopeBytes          = 4 << 10
)

var (
	ErrInvalidAccessToken          = errors.New("invalid access token")
	ErrAccessTokenKeyUnavailable   = errors.New("access token key unavailable")
	ErrAccessTokenScopeUnavailable = errors.New("access token scope unavailable")
)

type AccessTokenVerifier struct {
	issuer      string
	audience    string
	groupsClaim string
	jwksURL     string
	client      *http.Client
	now         func() time.Time

	cache jwksCache
}

type strictDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	JWKSURI                           string   `json:"jwks_uri"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
}

func NewAccessTokenVerifier(ctx context.Context, issuer, audience, groupsClaim string, client *http.Client) (*AccessTokenVerifier, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = http.DefaultClient
	}
	if err := validateStrictHTTPSURL("OIDC_ISSUER_URL", issuer, false); err != nil {
		return nil, err
	}
	if err := validateStrictResourceOrigin("PUBLIC_BASE_URL", audience); err != nil {
		return nil, err
	}
	document, err := fetchStrictDiscovery(ctx, client, issuer)
	if err != nil {
		return nil, err
	}
	return newAccessTokenVerifierFromDiscovery(issuer, audience, groupsClaim, client, document)
}

func newAccessTokenVerifierFromDiscovery(issuer, audience, groupsClaim string, client *http.Client, document strictDiscoveryDocument) (*AccessTokenVerifier, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if document.Issuer != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch")
	}
	for name, value := range map[string]string{
		"jwks_uri":               document.JWKSURI,
		"authorization_endpoint": document.AuthorizationEndpoint,
		"token_endpoint":         document.TokenEndpoint,
	} {
		if err := validateStrictHTTPSURL(name, value, true); err != nil {
			return nil, err
		}
	}
	return &AccessTokenVerifier{
		issuer:      issuer,
		audience:    audience,
		groupsClaim: groupsClaim,
		jwksURL:     document.JWKSURI,
		client:      client,
		now:         time.Now,
	}, nil
}

func (v *AccessTokenVerifier) Verify(ctx context.Context, raw string) (caller.Caller, error) {
	if v == nil {
		return caller.Caller{}, ErrAccessTokenKeyUnavailable
	}
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA})
	if err != nil || len(token.Headers) != 1 {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	header := token.Headers[0]
	if !allowedAccessTokenAlgorithm(header.Algorithm) || strings.TrimSpace(header.KeyID) == "" {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	if header.JSONWebKey != nil || header.ExtraHeaders[jose.HeaderKey("jku")] != nil || header.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	if !validAccessTokenType(header) {
		return caller.Caller{}, ErrInvalidAccessToken
	}

	keySet, err := v.cache.keysForKID(ctx, v, header.KeyID)
	if err != nil {
		return caller.Caller{}, err
	}
	var claims jwt.Claims
	custom := make(map[string]any)
	if err := token.Claims(keySet, &claims, &custom); err != nil {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	now := v.now()
	if err := validateRegisteredAccessTokenClaims(claims, v.issuer, v.audience, now); err != nil {
		return caller.Caller{}, err
	}
	if clientID, ok := custom["client_id"].(string); !ok || strings.TrimSpace(clientID) == "" {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	scopes, err := parseAccessTokenScopes(custom)
	if err != nil {
		return caller.Caller{}, err
	}
	principal, err := PrincipalFromVerifiedClaims(v.issuer, custom, v.groupsClaim, claims.Expiry.Time())
	if err != nil {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	actor, err := caller.NewBearer(principal.Issuer, principal.Subject, principal.Groups, scopes)
	if err != nil {
		return caller.Caller{}, ErrInvalidAccessToken
	}
	return actor, nil
}

func (a *Authenticator) VerifyAccessToken(ctx context.Context, raw string) (caller.Caller, error) {
	if a == nil || a.Config.Mode != config.AuthModeNative || a.Access == nil {
		return caller.Caller{}, ErrAccessTokenKeyUnavailable
	}
	return a.Access.Verify(ctx, raw)
}

func allowedAccessTokenAlgorithm(algorithm string) bool {
	switch jose.SignatureAlgorithm(algorithm) {
	case jose.RS256, jose.PS256, jose.ES256, jose.EdDSA:
		return true
	default:
		return false
	}
}

func validAccessTokenType(header jose.Header) bool {
	value, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if value == "" || strings.ContainsAny(value, ";\t\r\n ") {
		return false
	}
	folded := asciiLower(value)
	return folded == "at+jwt" || folded == "application/at+jwt"
}

func validateRegisteredAccessTokenClaims(claims jwt.Claims, issuer, audience string, now time.Time) error {
	if claims.Issuer != issuer || strings.TrimSpace(claims.Subject) == "" || claims.ID == "" || claims.Expiry == nil || claims.IssuedAt == nil {
		return ErrInvalidAccessToken
	}
	if !claims.Audience.Contains(audience) {
		return ErrInvalidAccessToken
	}
	if now.After(claims.Expiry.Time().Add(accessTokenSkew)) {
		return ErrInvalidAccessToken
	}
	if now.Add(accessTokenSkew).Before(claims.IssuedAt.Time()) {
		return ErrInvalidAccessToken
	}
	if claims.NotBefore != nil && now.Add(accessTokenSkew).Before(claims.NotBefore.Time()) {
		return ErrInvalidAccessToken
	}
	return nil
}

func parseAccessTokenScopes(claims map[string]any) ([]string, error) {
	if _, exists := claims["scp"]; exists {
		return nil, ErrInvalidAccessToken
	}
	raw, exists := claims["scope"]
	if !exists {
		return nil, nil
	}
	scopeString, ok := raw.(string)
	if !ok || len(scopeString) > maxScopeBytes {
		return nil, ErrInvalidAccessToken
	}
	if scopeString == "" {
		return nil, ErrInvalidAccessToken
	}
	if strings.Contains(scopeString, "\t") || strings.Contains(scopeString, "\n") || strings.Contains(scopeString, "\r") {
		return nil, ErrInvalidAccessToken
	}
	parts := strings.Split(scopeString, " ")
	scopes := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, scope := range parts {
		if scope == "" || !validScopeToken(scope) {
			return nil, ErrInvalidAccessToken
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, ErrInvalidAccessToken
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func validScopeToken(scope string) bool {
	for _, r := range scope {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func fetchStrictDiscovery(ctx context.Context, client *http.Client, issuer string) (strictDiscoveryDocument, error) {
	discoveryURL, err := oidcDiscoveryURL(issuer)
	if err != nil {
		return strictDiscoveryDocument{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, accessTokenHTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return strictDiscoveryDocument{}, err
	}
	response, err := doOIDCRequest(client, request)
	if err != nil {
		return strictDiscoveryDocument{}, fmt.Errorf("OIDC discovery failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return strictDiscoveryDocument{}, fmt.Errorf("OIDC discovery failed")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	var document strictDiscoveryDocument
	if err := decoder.Decode(&document); err != nil {
		return strictDiscoveryDocument{}, fmt.Errorf("OIDC discovery failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return strictDiscoveryDocument{}, fmt.Errorf("OIDC discovery failed")
	}
	return document, nil
}

func doOIDCRequest(client *http.Client, request *http.Request) (*http.Response, error) {
	strictClient := *client
	strictClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return strictClient.Do(request)
}

func oidcDiscoveryURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("OIDC_ISSUER_URL must be an absolute HTTPS URL")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if path == "" {
		path = "/.well-known/openid-configuration"
	} else {
		path += "/.well-known/openid-configuration"
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func validateStrictHTTPSURL(name, raw string, forbidQueryFragment bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || strings.ToLower(parsed.Scheme) != "https" {
		return fmt.Errorf("%s must be an absolute HTTPS URL", name)
	}
	if forbidQueryFragment && (parsed.RawQuery != "" || parsed.Fragment != "") {
		return fmt.Errorf("%s must not contain a query or fragment", name)
	}
	return nil
}

func validateStrictResourceOrigin(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || strings.ToLower(parsed.Scheme) != "https" {
		return fmt.Errorf("%s must be an HTTPS origin", name)
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an HTTPS origin", name)
	}
	return nil
}

func asciiLower(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		builder.WriteByte(b)
	}
	return builder.String()
}

type jwksCache struct {
	mu                    sync.Mutex
	refreshGroup          singleflight.Group
	keys                  jose.JSONWebKeySet
	haveKeys              bool
	noStore               bool
	noCache               bool
	mustRevalidate        bool
	proxyRevalidate       bool
	sMaxage               bool
	expiry                time.Time
	staleUntil            time.Time
	etag                  string
	lastModified          string
	responseHeaders       http.Header
	lastUnknownKIDRefresh time.Time
	lastUnknownKIDExpiry  time.Time
	lastUnknownKIDKeys    map[string]struct{}
	lastUnknownKIDSuccess bool
}

func (c *jwksCache) keysForKID(ctx context.Context, verifier *AccessTokenVerifier, kid string) (jose.JSONWebKeySet, error) {
	now := verifier.now()
	c.mu.Lock()

	if c.haveKeys && !c.revalidationRequired(now) {
		if c.containsKIDLocked(kid) {
			keys := c.keys
			c.mu.Unlock()
			return keys, nil
		}
	}
	unknownKID := !c.containsKIDLocked(kid)
	if unknownKID {
		if err := c.unknownKIDThrottleLocked(now, kid); err != nil {
			c.mu.Unlock()
			return jose.JSONWebKeySet{}, err
		}
	}
	c.mu.Unlock()

	owner := new(byte)
	result, err, _ := c.refreshGroup.Do("jwks", func() (any, error) {
		refreshNow := verifier.now()
		c.mu.Lock()
		if c.haveKeys && !c.revalidationRequired(refreshNow) {
			if c.containsKIDLocked(kid) {
				keys := c.keys
				c.mu.Unlock()
				return jwksRefreshResult{keys: keys, retained: true, owner: owner}, nil
			}
		}
		unknownKID := !c.containsKIDLocked(kid)
		if unknownKID {
			if err := c.unknownKIDThrottleLocked(refreshNow, kid); err != nil {
				c.mu.Unlock()
				return jwksRefreshResult{}, err
			}
		}
		conditional := jwksConditionalRequest{ETag: c.etag, LastModified: c.lastModified}
		c.mu.Unlock()
		keys, retained, err := c.refresh(ctx, verifier, conditional, refreshNow)
		c.recordUnknownKIDOutcome(verifier.now(), kid, unknownKID, keys, err)
		return jwksRefreshResult{keys: keys, retained: retained, owner: owner, unknownKID: unknownKID}, err
	})
	if err != nil {
		if errors.Is(err, ErrInvalidAccessToken) {
			return jose.JSONWebKeySet{}, ErrInvalidAccessToken
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.haveKeys && c.staleAllowed(verifier.now()) && c.containsKIDLocked(kid) {
			return c.keys, nil
		}
		return jose.JSONWebKeySet{}, ErrAccessTokenKeyUnavailable
	}
	refresh := result.(jwksRefreshResult)
	if !refresh.retained && refresh.owner != owner {
		if refresh.unknownKID {
			c.mu.Lock()
			throttleErr := c.unknownKIDThrottleLocked(verifier.now(), kid)
			c.mu.Unlock()
			if throttleErr != nil {
				return jose.JSONWebKeySet{}, throttleErr
			}
		}
		keys, retained, refreshErr := c.refresh(ctx, verifier, jwksConditionalRequest{}, verifier.now())
		c.recordUnknownKIDOutcome(verifier.now(), kid, refresh.unknownKID, keys, refreshErr)
		if refreshErr != nil {
			return jose.JSONWebKeySet{}, ErrAccessTokenKeyUnavailable
		}
		refresh = jwksRefreshResult{keys: keys, retained: retained, owner: owner, unknownKID: refresh.unknownKID}
	}
	if refresh.retained && !keySetContains(refresh.keys, kid) {
		return jose.JSONWebKeySet{}, ErrInvalidAccessToken
	}
	if !refresh.retained && !keySetContains(refresh.keys, kid) {
		return jose.JSONWebKeySet{}, ErrInvalidAccessToken
	}
	return refresh.keys, nil
}

type jwksRefreshResult struct {
	keys       jose.JSONWebKeySet
	retained   bool
	owner      *byte
	unknownKID bool
}

func (c *jwksCache) unknownKIDThrottleLocked(now time.Time, kid string) error {
	if c.lastUnknownKIDRefresh.IsZero() || !now.Before(c.lastUnknownKIDRefresh.Add(time.Minute)) {
		return nil
	}
	if !c.lastUnknownKIDSuccess {
		return ErrAccessTokenKeyUnavailable
	}
	if _, present := c.lastUnknownKIDKeys[kid]; present {
		return nil
	}
	// A successful result obtained before the retained cache expired does not
	// satisfy the next mandatory revalidation. Allow that one fetch, but keep
	// the successful absence proof for cold and no-store caches.
	if !c.lastUnknownKIDExpiry.IsZero() && !c.expiry.IsZero() && !now.Before(c.expiry) && c.lastUnknownKIDExpiry.After(c.lastUnknownKIDRefresh) {
		return nil
	}
	return ErrInvalidAccessToken
}

func (c *jwksCache) recordUnknownKIDOutcome(now time.Time, kid string, unknownKID bool, keys jose.JSONWebKeySet, refreshErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !unknownKID {
		return
	}
	if refreshErr == nil && keySetContains(keys, kid) {
		c.lastUnknownKIDRefresh = time.Time{}
		c.lastUnknownKIDExpiry = time.Time{}
		c.lastUnknownKIDKeys = nil
		c.lastUnknownKIDSuccess = false
		return
	}
	c.lastUnknownKIDRefresh = now
	c.lastUnknownKIDExpiry = c.expiry
	if refreshErr != nil {
		c.lastUnknownKIDSuccess = false
		c.lastUnknownKIDKeys = nil
		return
	}
	c.lastUnknownKIDSuccess = true
	c.lastUnknownKIDKeys = make(map[string]struct{}, len(keys.Keys))
	for _, key := range keys.Keys {
		if key.KeyID != "" {
			c.lastUnknownKIDKeys[key.KeyID] = struct{}{}
		}
	}
}

func (c *jwksCache) revalidationRequired(now time.Time) bool {
	return c.noCache || c.noStore || c.expiry.IsZero() || !now.Before(c.expiry)
}

func (c *jwksCache) staleAllowed(now time.Time) bool {
	if c.noStore || c.noCache || c.mustRevalidate || c.proxyRevalidate || c.sMaxage || c.staleUntil.IsZero() {
		return false
	}
	return now.Before(c.staleUntil)
}

func (c *jwksCache) containsKIDLocked(kid string) bool {
	return keySetContains(c.keys, kid)
}

func keySetContains(keys jose.JSONWebKeySet, kid string) bool {
	return len(keys.Key(kid)) > 0
}

type jwksConditionalRequest struct {
	ETag         string
	LastModified string
}

func (c *jwksCache) refresh(ctx context.Context, verifier *AccessTokenVerifier, conditional jwksConditionalRequest, now time.Time) (jose.JSONWebKeySet, bool, error) {
	requestContext, cancel := context.WithTimeout(ctx, accessTokenHTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, verifier.jwksURL, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, false, err
	}
	if conditional.ETag != "" {
		request.Header.Set("If-None-Match", conditional.ETag)
	}
	if conditional.LastModified != "" {
		request.Header.Set("If-Modified-Since", conditional.LastModified)
	}
	response, err := doOIDCRequest(verifier.client, request)
	if err != nil {
		return jose.JSONWebKeySet{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.haveKeys && !c.noStore {
			mergedHeaders := mergeRevalidatedHeaders(c.responseHeaders, response.Header)
			directives := parseCacheDirectives(mergedHeaders, now)
			c.applyDirectivesLocked(directives, mergedHeaders, now)
			return c.keys, true, nil
		}
		return jose.JSONWebKeySet{}, false, ErrAccessTokenKeyUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, false, ErrAccessTokenKeyUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	var keys jose.JSONWebKeySet
	if err := decoder.Decode(&keys); err != nil {
		return jose.JSONWebKeySet{}, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return jose.JSONWebKeySet{}, false, ErrAccessTokenKeyUnavailable
	}
	directives := parseCacheDirectives(response.Header, now)
	if directives.noStore {
		c.mu.Lock()
		c.keys = jose.JSONWebKeySet{}
		c.haveKeys = false
		c.noStore = true
		c.noCache = false
		c.mustRevalidate = false
		c.proxyRevalidate = false
		c.sMaxage = false
		c.expiry = time.Time{}
		c.staleUntil = time.Time{}
		c.etag = ""
		c.lastModified = ""
		c.responseHeaders = nil
		c.mu.Unlock()
		return keys, false, nil
	}
	c.mu.Lock()
	c.keys = keys
	c.haveKeys = true
	c.applyDirectivesLocked(directives, response.Header, now)
	c.mu.Unlock()
	return keys, true, nil
}

func (c *jwksCache) applyDirectivesLocked(d cacheDirectives, header http.Header, now time.Time) {
	c.noStore = d.noStore
	c.noCache = d.noCache || d.freshness <= 0
	c.mustRevalidate = d.mustRevalidate
	c.proxyRevalidate = d.proxyRevalidate
	c.sMaxage = d.sMaxage
	c.expiry = now.Add(d.freshness)
	if c.noCache || c.noStore || c.mustRevalidate || c.proxyRevalidate || c.sMaxage {
		c.staleUntil = time.Time{}
	} else {
		grace := jwksMaxStaleUse
		if d.staleIfError >= 0 && d.staleIfError < grace {
			grace = d.staleIfError
		}
		c.staleUntil = c.expiry.Add(grace)
	}
	c.etag = header.Get("ETag")
	c.lastModified = header.Get("Last-Modified")
	c.responseHeaders = header.Clone()
}

func mergeRevalidatedHeaders(stored, revalidated http.Header) http.Header {
	merged := stored.Clone()
	if merged == nil {
		merged = make(http.Header)
	}
	for name, values := range revalidated {
		merged[name] = append([]string(nil), values...)
	}
	return merged
}

type cacheDirectives struct {
	noStore         bool
	noCache         bool
	mustRevalidate  bool
	proxyRevalidate bool
	sMaxage         bool
	freshness       time.Duration
	staleIfError    time.Duration
}

func parseCacheDirectives(header http.Header, now time.Time) cacheDirectives {
	directives := cacheDirectives{freshness: jwksDefaultFreshness, staleIfError: jwksMaxStaleUse}
	cacheControl := strings.Join(header.Values("Cache-Control"), ",")
	values := map[string]string{}
	for _, part := range strings.Split(cacheControl, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		name, value, found := strings.Cut(item, "=")
		name = asciiLower(strings.TrimSpace(name))
		if found {
			value = strings.Trim(strings.TrimSpace(value), `"`)
		}
		values[name] = value
	}
	if _, ok := values["no-store"]; ok {
		directives.noStore = true
	}
	if _, ok := values["no-cache"]; ok {
		directives.noCache = true
	}
	if _, ok := values["must-revalidate"]; ok {
		directives.mustRevalidate = true
	}
	if _, ok := values["proxy-revalidate"]; ok {
		directives.proxyRevalidate = true
	}
	baseDate := headerTime(header.Get("Date"), now)
	currentAge := time.Duration(0)
	if ageHeader := header.Get("Age"); ageHeader != "" {
		if seconds, err := strconv.ParseInt(strings.TrimSpace(ageHeader), 10, 64); err == nil && seconds > 0 {
			currentAge += time.Duration(seconds) * time.Second
		}
	}
	if apparent := now.Sub(baseDate); apparent > currentAge {
		currentAge = apparent
	}
	if value, ok := values["s-maxage"]; ok {
		if lifetime, parsed := secondsDuration(value); parsed {
			directives.sMaxage = true
			directives.freshness = lifetime - currentAge
		}
	} else if value, ok := values["max-age"]; ok {
		if lifetime, parsed := secondsDuration(value); parsed {
			directives.freshness = lifetime - currentAge
		}
	} else if expires := header.Get("Expires"); expires != "" {
		if expiresAt, err := http.ParseTime(expires); err == nil {
			directives.freshness = expiresAt.Sub(baseDate) - currentAge
		}
	}
	if directives.freshness > jwksMaxFreshness {
		directives.freshness = jwksMaxFreshness
	}
	if directives.freshness > 0 && directives.freshness < jwksMinFreshness {
		directives.freshness = jwksMinFreshness
	}
	if value, ok := values["stale-if-error"]; ok {
		if lifetime, parsed := secondsDuration(value); parsed {
			directives.staleIfError = lifetime
		}
	}
	return directives
}

func secondsDuration(raw string) (time.Duration, bool) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func headerTime(raw string, fallback time.Time) time.Time {
	if raw == "" {
		return fallback
	}
	value, err := http.ParseTime(raw)
	if err != nil {
		return fallback
	}
	return value
}
