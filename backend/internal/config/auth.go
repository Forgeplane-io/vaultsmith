package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	authModeEnv              = "AUTH_MODE"
	defaultSessionCookieName = "__Host-vaultsmith_session"
	defaultGroupsClaim       = "groups"
	defaultAbsoluteLifetime  = 8 * time.Hour
	defaultIdleLifetime      = 30 * time.Minute
	defaultRedisConnect      = 5 * time.Second
	defaultRedisRead         = 5 * time.Second
	defaultRedisWrite        = 5 * time.Second
	defaultRedisPoolSize     = 10
	defaultRefreshLockTTL    = 15 * time.Second
	defaultRefreshLockWait   = 250 * time.Millisecond
	defaultRefreshLockRetry  = 25 * time.Millisecond
	defaultProviderTimeout   = 10 * time.Second
	minSecretLength          = 32
)

type AuthMode string

const (
	AuthModeNative AuthMode = "native"
	AuthModeOff    AuthMode = "off"
)

type EnvLookup func(string) (string, bool)

type AuthConfig struct {
	Mode    AuthMode
	OIDC    OIDCConfig
	Session SessionConfig
	Redis   RedisConfig
	CSRF    CSRFConfig
	CORS    CORSConfig
	Policy  PolicyConfig
}

type OIDCConfig struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	CAFile        string
	RedirectURL   string
	PublicBaseURL string
	Scopes        []string
	GroupsClaim   string
}

type SessionConfig struct {
	CookieName       string
	AbsoluteLifetime time.Duration
	IdleLifetime     time.Duration
	Secure           bool
	SameSite         http.SameSite
}

type RedisConfig struct {
	Address          string
	Username         string
	Password         string
	Database         int
	TLS              bool
	ConnectTimeout   time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	PoolSize         int
	RefreshLockTTL   time.Duration
	RefreshLockWait  time.Duration
	RefreshLockRetry time.Duration
	ProviderTimeout  time.Duration
	KeyPrefix        string
}

type CSRFConfig struct {
	Secret string
}

type CORSConfig struct {
	AllowedOrigins []string
}

type PolicyConfig struct {
	File string
}

// LoadAuth loads the authentication contract from environment variables. The
// lookup parameter exists so validation can be tested without mutating the
// process environment. Secret values are retained only in the returned
// runtime configuration and are never included in validation errors.
func LoadAuth(lookup EnvLookup) (*AuthConfig, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	mode, err := parseAuthMode(lookup)
	if err != nil {
		return nil, err
	}

	csrfSecret := ""
	if mode == AuthModeNative {
		csrfSecret, err = requiredSecret(lookup, "CSRF_SECRET")
		if err != nil {
			return nil, err
		}
		if len([]byte(csrfSecret)) < minSecretLength {
			return nil, fmt.Errorf("CSRF_SECRET must be at least %d bytes", minSecretLength)
		}
	}

	cfg := &AuthConfig{
		Mode: mode,
		Session: SessionConfig{
			CookieName: defaultSessionCookieName,
			Secure:     mode == AuthModeNative,
			SameSite:   http.SameSiteLaxMode,
		},
		Redis: RedisConfig{PoolSize: defaultRedisPoolSize},
		CSRF:  CSRFConfig{Secret: csrfSecret},
		OIDC: OIDCConfig{
			GroupsClaim: defaultGroupsClaim,
			Scopes:      []string{"openid", "profile", "offline_access"},
		},
	}

	if err := parseCommonAuthOptions(cfg, lookup); err != nil {
		return nil, err
	}
	if err := parseRedisOptions(&cfg.Redis, lookup, mode == AuthModeNative); err != nil {
		return nil, err
	}

	if mode == AuthModeNative {
		if err := parseNativeOptions(cfg, lookup); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func parseAuthMode(lookup EnvLookup) (AuthMode, error) {
	raw, ok := lookup(authModeEnv)
	if !ok || strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%s must be explicitly set to %q or %q", authModeEnv, AuthModeNative, AuthModeOff)
	}
	switch AuthMode(strings.TrimSpace(raw)) {
	case AuthModeNative:
		return AuthModeNative, nil
	case AuthModeOff:
		return AuthModeOff, nil
	default:
		return "", fmt.Errorf("%s must be %q or %q", authModeEnv, AuthModeNative, AuthModeOff)
	}
}

func parseCommonAuthOptions(cfg *AuthConfig, lookup EnvLookup) error {
	var err error
	if cfg.Session.AbsoluteLifetime, err = durationOption(lookup, "SESSION_ABSOLUTE_LIFETIME", defaultAbsoluteLifetime); err != nil {
		return err
	}
	if cfg.Session.IdleLifetime, err = durationOption(lookup, "SESSION_IDLE_LIFETIME", defaultIdleLifetime); err != nil {
		return err
	}
	if cfg.Session.AbsoluteLifetime <= 0 || cfg.Session.IdleLifetime <= 0 {
		return errors.New("session lifetimes must be positive")
	}
	if cfg.Session.IdleLifetime > cfg.Session.AbsoluteLifetime {
		return errors.New("SESSION_IDLE_LIFETIME cannot exceed SESSION_ABSOLUTE_LIFETIME")
	}

	if raw, ok := lookup("COOKIE_SECURE"); ok && strings.TrimSpace(raw) != "" {
		cfg.Session.Secure, err = boolOption("COOKIE_SECURE", raw)
		if err != nil {
			return err
		}
	}
	if raw, ok := lookup("COOKIE_SAME_SITE"); ok && strings.TrimSpace(raw) != "" {
		cfg.Session.SameSite, err = sameSiteOption(raw)
		if err != nil {
			return err
		}
	}

	corsRaw, _ := lookup("CORS_ALLOWED_ORIGINS")
	cfg.CORS.AllowedOrigins, err = parseOrigins(corsRaw)
	if err != nil {
		return err
	}
	if cfg.Session.SameSite == http.SameSiteNoneMode {
		if !cfg.Session.Secure {
			return errors.New("COOKIE_SAME_SITE=none requires COOKIE_SECURE=true")
		}
		if len(cfg.CORS.AllowedOrigins) == 0 {
			return errors.New("COOKIE_SAME_SITE=none requires CORS_ALLOWED_ORIGINS")
		}
	}
	return nil
}

func parseNativeOptions(cfg *AuthConfig, lookup EnvLookup) error {
	issuer, err := requiredValue(lookup, "OIDC_ISSUER_URL")
	if err != nil {
		return err
	}
	issuerURL, err := validateWebURL("OIDC_ISSUER_URL", issuer, false)
	if err != nil {
		return err
	}
	if issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return errors.New("OIDC_ISSUER_URL must not contain a query or fragment")
	}
	if raw, ok := lookup("OIDC_CA_FILE"); ok && strings.TrimSpace(raw) != "" {
		caFile := strings.TrimSpace(raw)
		info, err := os.Stat(caFile)
		if err != nil || info.IsDir() {
			return errors.New("OIDC_CA_FILE is unavailable")
		}
		cfg.OIDC.CAFile = caFile
	}

	clientID, err := requiredValue(lookup, "OIDC_CLIENT_ID")
	if err != nil {
		return err
	}
	clientSecret, err := requiredSecret(lookup, "OIDC_CLIENT_SECRET")
	if err != nil {
		return err
	}
	redirect, err := requiredValue(lookup, "OIDC_REDIRECT_URL")
	if err != nil {
		return err
	}
	redirectURL, err := validateWebURL("OIDC_REDIRECT_URL", redirect, false)
	if err != nil {
		return err
	}
	if redirectURL.RawQuery != "" || redirectURL.Fragment != "" {
		return errors.New("OIDC_REDIRECT_URL must not contain a query or fragment")
	}
	publicBase, err := requiredValue(lookup, "PUBLIC_BASE_URL")
	if err != nil {
		return err
	}
	publicBaseURL, err := validateResourceOrigin("PUBLIC_BASE_URL", publicBase)
	if err != nil {
		return err
	}
	if !sameOrigin(publicBaseURL, redirectURL) {
		return errors.New("OIDC_REDIRECT_URL must use the PUBLIC_BASE_URL origin")
	}
	if !cfg.Session.Secure {
		return errors.New("native mode requires COOKIE_SECURE=true")
	}
	if cfg.Session.SameSite == http.SameSiteStrictMode {
		return errors.New("native mode does not support COOKIE_SAME_SITE=strict because the OIDC callback is cross-site")
	}

	cfg.OIDC.IssuerURL = issuerURL.String()
	cfg.OIDC.ClientID = clientID
	cfg.OIDC.ClientSecret = clientSecret
	cfg.OIDC.RedirectURL = redirectURL.String()
	cfg.OIDC.PublicBaseURL = canonicalOrigin(publicBaseURL)
	if raw, ok := lookup("OIDC_GROUPS_CLAIM"); ok && strings.TrimSpace(raw) != "" {
		claim := strings.TrimSpace(raw)
		if !validClaimPath(claim) {
			return errors.New("OIDC_GROUPS_CLAIM has invalid syntax")
		}
		cfg.OIDC.GroupsClaim = claim
	}
	if raw, ok := lookup("OIDC_SCOPES"); ok && strings.TrimSpace(raw) != "" {
		scopes, err := parseScopes(raw)
		if err != nil {
			return err
		}
		cfg.OIDC.Scopes = scopes
	}
	if !slices.Contains(cfg.OIDC.Scopes, "openid") {
		return errors.New("OIDC_SCOPES must include openid")
	}

	policyFile, err := requiredValue(lookup, "AUTHZ_POLICY_FILE")
	if err != nil {
		return err
	}
	cfg.Policy.File = policyFile
	return nil
}

func LoadMCPEnabled(lookup EnvLookup) (bool, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	raw, ok := lookup("MCP_ENABLED")
	if !ok {
		return false, nil
	}
	if raw == "" {
		return false, errors.New("MCP_ENABLED must be true or false")
	}
	return boolOption("MCP_ENABLED", raw)
}

func RejectMCPGoDebug(lookup EnvLookup) error {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if raw, ok := lookup("MCPGODEBUG"); ok && raw != "" {
		return errors.New("MCPGODEBUG must be unset or empty")
	}
	return nil
}

func parseRedisOptions(cfg *RedisConfig, lookup EnvLookup, required bool) error {
	if address, ok := lookup("REDIS_ADDR"); ok && strings.TrimSpace(address) != "" {
		cfg.Address = strings.TrimSpace(address)
	} else if required {
		return errors.New("REDIS_ADDR is required in native mode")
	}
	if raw, ok := lookup("REDIS_USERNAME"); ok {
		cfg.Username = raw
	}
	if raw, ok := lookup("REDIS_PASSWORD"); ok {
		cfg.Password = raw
	}
	if cfg.Username != "" && cfg.Password == "" {
		return errors.New("REDIS_PASSWORD is required when REDIS_USERNAME is configured")
	}
	var err error
	if raw, ok := lookup("REDIS_DB"); ok && strings.TrimSpace(raw) != "" {
		cfg.Database, err = intOption("REDIS_DB", raw)
		if err != nil || cfg.Database < 0 {
			return errors.New("REDIS_DB must be a non-negative integer")
		}
	}
	if raw, ok := lookup("REDIS_TLS"); ok && strings.TrimSpace(raw) != "" {
		cfg.TLS, err = boolOption("REDIS_TLS", raw)
		if err != nil {
			return err
		}
	}
	if cfg.ConnectTimeout, err = durationOption(lookup, "REDIS_CONNECT_TIMEOUT", defaultRedisConnect); err != nil {
		return err
	}
	if cfg.ReadTimeout, err = durationOption(lookup, "REDIS_READ_TIMEOUT", defaultRedisRead); err != nil {
		return err
	}
	if cfg.WriteTimeout, err = durationOption(lookup, "REDIS_WRITE_TIMEOUT", defaultRedisWrite); err != nil {
		return err
	}
	if cfg.ConnectTimeout <= 0 || cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 {
		return errors.New("redis timeouts must be positive")
	}
	if raw, ok := lookup("REDIS_POOL_SIZE"); ok && strings.TrimSpace(raw) != "" {
		cfg.PoolSize, err = intOption("REDIS_POOL_SIZE", raw)
		if err != nil || cfg.PoolSize <= 0 {
			return errors.New("REDIS_POOL_SIZE must be a positive integer")
		}
	}
	if cfg.RefreshLockTTL, err = durationOption(lookup, "REDIS_REFRESH_LOCK_TTL", defaultRefreshLockTTL); err != nil {
		return err
	}
	if cfg.RefreshLockWait, err = durationOption(lookup, "REDIS_REFRESH_LOCK_WAIT", defaultRefreshLockWait); err != nil {
		return err
	}
	if cfg.RefreshLockRetry, err = durationOption(lookup, "REDIS_REFRESH_LOCK_RETRY", defaultRefreshLockRetry); err != nil {
		return err
	}
	if cfg.ProviderTimeout, err = durationOption(lookup, "REDIS_PROVIDER_TIMEOUT", defaultProviderTimeout); err != nil {
		return err
	}
	if cfg.RefreshLockTTL <= 0 || cfg.RefreshLockWait <= 0 || cfg.RefreshLockRetry <= 0 || cfg.ProviderTimeout <= 0 {
		return errors.New("redis refresh lock and provider timeouts must be positive")
	}
	if cfg.RefreshLockTTL <= cfg.ProviderTimeout {
		return errors.New("REDIS_REFRESH_LOCK_TTL must exceed REDIS_PROVIDER_TIMEOUT")
	}
	prefix, ok := lookup("REDIS_KEY_PREFIX")
	if required && (!ok || strings.TrimSpace(prefix) == "") {
		return errors.New("REDIS_KEY_PREFIX is required in native mode")
	}
	if ok && strings.TrimSpace(prefix) != "" {
		cfg.KeyPrefix = prefix
		if !validRedisPrefix(prefix) {
			return errors.New("REDIS_KEY_PREFIX must be a safe prefix ending with a colon")
		}
	}
	return nil
}

func requiredValue(lookup EnvLookup, key string) (string, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return strings.TrimSpace(value), nil
}

func requiredSecret(lookup EnvLookup, key string) (string, error) {
	value, ok := lookup(key)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func durationOption(lookup EnvLookup, key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := lookup(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration", key)
	}
	return value, nil
}

func boolOption(key, raw string) (bool, error) {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return value, nil
}

func intOption(key, raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return value, nil
}

func sameSiteOption(raw string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return 0, errors.New("COOKIE_SAME_SITE must be lax, strict, or none")
	}
}

func parseScopes(raw string) ([]string, error) {
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil, errors.New("OIDC_SCOPES must not be empty")
	}
	seen := make(map[string]struct{}, len(parts))
	for _, scope := range parts {
		if _, exists := seen[scope]; exists {
			return nil, errors.New("OIDC_SCOPES contains duplicate values")
		}
		seen[scope] = struct{}{}
	}
	return parts, nil
}

func parseOrigins(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	origins := make([]string, 0)
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(part)
		if origin == "" || origin == "*" {
			return nil, errors.New("CORS_ALLOWED_ORIGINS must contain exact HTTPS origins or loopback HTTP origins")
		}
		u, err := validateWebURL("CORS_ALLOWED_ORIGINS", origin, true)
		if err != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("CORS_ALLOWED_ORIGINS must contain exact HTTPS origins or loopback HTTP origins")
		}
		canonical := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("CORS_ALLOWED_ORIGINS contains duplicate origins")
		}
		seen[canonical] = struct{}{}
		origins = append(origins, canonical)
	}
	return origins, nil
}

func validateWebURL(key, raw string, allowLoopbackHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL", key)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(allowLoopbackHTTP && scheme == "http" && isLoopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("%s must use HTTPS except for loopback development URLs", key)
	}
	return u, nil
}

func validateResourceOrigin(key, raw string) (*url.URL, error) {
	u, err := validateWebURL(key, raw, false)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%s must be an HTTPS origin without an application path", key)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain a query or fragment", key)
	}
	return u, nil
}

func canonicalOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func validClaimPath(claim string) bool {
	if claim == "" {
		return false
	}
	for _, part := range strings.Split(claim, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validRedisPrefix(prefix string) bool {
	if len(prefix) < 2 || len(prefix) > 128 || !strings.HasSuffix(prefix, ":") {
		return false
	}
	for index, r := range prefix {
		if index == 0 && !(unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/-", r)) {
			return false
		}
	}
	return true
}
