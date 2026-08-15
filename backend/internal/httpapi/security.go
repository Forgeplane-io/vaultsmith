package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type Dependencies struct {
	Auth              *authn.Authenticator
	Authorizer        *authz.Authorizer
	AuthConfig        config.AuthConfig
	Admission         *vaultservice.Admission
	VerifierAdmission *vaultservice.Admission
	Service           *vaultservice.Service
}

type SecurityOptions struct {
	Auth       *authn.Authenticator
	MCPEnabled bool
}

func NewWithDependencies(profiles []Profile, executor Executor, dependencies Dependencies) http.Handler {
	serviceProfiles := make([]vaultservice.Profile, 0, len(profiles))
	for _, profile := range profiles {
		serviceProfiles = append(serviceProfiles, vaultservice.Profile{ID: profile.ID, Label: profile.Label})
	}
	service := dependencies.Service
	if service == nil {
		service = vaultservice.NewWithOptions(
			serviceProfiles,
			executor,
			dependencies.Authorizer,
			dependencies.Admission,
			vaultservice.ServiceOptions{VerifierAdmission: dependencies.VerifierAdmission},
		)
	}
	return &Handler{
		service:    service,
		auth:       dependencies.Auth,
		authConfig: dependencies.AuthConfig,
	}
}

func WrapSecurity(next http.Handler, cfg config.AuthConfig) http.Handler {
	return WrapSecurityWithOptions(next, cfg, SecurityOptions{})
}

func WrapSecurityWithOptions(next http.Handler, cfg config.AuthConfig, options SecurityOptions) http.Handler {
	if cfg.Mode == config.AuthModeNative && options.Auth == nil {
		next = csrfMiddleware(next, cfg)
		next = legacyCredentialDispatchMiddleware(next, cfg)
		next = corsMiddleware(next, cfg, options.MCPEnabled)
		next = mcpMethodMiddleware(next, options.MCPEnabled)
		next = disabledMCPMiddleware(next, options.MCPEnabled)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ensureRequestID(w)
			setSecurityHeaders(w)
			next.ServeHTTP(w, r)
		})
	}
	next = applicationDeadlineMiddleware(next)
	next = credentialDispatchMiddleware(next, cfg, options)
	next = applicationPreflightMiddleware(next, options.MCPEnabled)
	next = corsMiddleware(next, cfg, options.MCPEnabled)
	next = mcpMethodMiddleware(next, options.MCPEnabled)
	next = disabledMCPMiddleware(next, options.MCPEnabled)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ensureRequestID(w)
		setSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func disabledMCPMiddleware(next http.Handler, enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" && !enabled {
			writeError(w, http.StatusNotFound, "not_found", "resource was not found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mcpMethodMiddleware(next http.Handler, enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || !enabled || r.Method == http.MethodPost || validMCPPreflight(r) {
			next.ServeHTTP(w, r)
			return
		}
		methodNotAllowed(w, http.MethodPost)
	})
}

func validMCPPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		strings.TrimSpace(r.Header.Get("Origin")) != "" &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")), http.MethodPost)
}

func legacyCredentialDispatchMiddleware(next http.Handler, cfg config.AuthConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if legacySessionOnlyAPIMethod(r) && rejectUnsupportedAuthorization(w, r, cfg) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func legacySessionOnlyAPIMethod(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/profiles":
		return r.Method == http.MethodGet
	case "/api/v1/operations":
		return r.Method == http.MethodPost
	default:
		return false
	}
}

func applicationDeadlineMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !applicationDeadlineApplies(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func applicationDeadlineApplies(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return false
	}
	switch {
	case r.URL.Path == "/api/v1/profiles" && r.Method == http.MethodGet:
		return true
	case r.URL.Path == "/api/v1/operations" && r.Method == http.MethodPost:
		return true
	case r.URL.Path == "/api/v1/rotations" && r.Method == http.MethodPost:
		return true
	case canonicalOperationPath(r.URL) && r.Method == http.MethodPost:
		return true
	case r.URL.Path == "/api/v1/attestations/verify" && r.Method == http.MethodPost:
		return true
	case r.URL.Path == "/mcp" && r.Method == http.MethodPost:
		return true
	default:
		return false
	}
}

// applicationPreflightMiddleware completes route, method, and no-body header
// validation before the server-owned application deadline is installed. The
// route handlers repeat these checks for direct-handler tests and safe reuse.
func applicationPreflightMiddleware(next http.Handler, mcpEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validated, ok := preflightApplicationRequest(w, r, mcpEnabled)
		if !ok {
			return
		}
		next.ServeHTTP(w, validated)
	})
}

func preflightApplicationRequest(w http.ResponseWriter, r *http.Request, mcpEnabled bool) (*http.Request, bool) {
	if _, _, _, invalid := canonicalProfileOperation(r.URL); invalid {
		writeError(w, http.StatusBadRequest, "invalid_request", "profile ID is invalid")
		return r, false
	}
	switch {
	case r.URL.Path == "/api/v1/profiles":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return r, false
		}
	case r.URL.Path == "/api/v1/operations", r.URL.Path == "/api/v1/rotations", r.URL.Path == "/api/v1/attestations/verify", canonicalOperationPath(r.URL):
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return r, false
		}
		if !isJSONContentType(r.Header.Get("Content-Type")) {
			writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
			return r, false
		}
		if !supportsIdentityContentEncoding(r.Header) {
			writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
			return r, false
		}
	case r.URL.Path == "/mcp" && mcpEnabled:
		if r.Method != http.MethodPost {
			return r, true
		}
		if !isJSONContentType(r.Header.Get("Content-Type")) || !supportsIdentityContentEncoding(r.Header) {
			mcpWriteHTTPError(w, http.StatusUnsupportedMediaType, nil, mcpErrorInvalidRequest, "unsupported media type", nil)
			return r, false
		}
		if !mcpAccepts(r.Header.Values("Accept")) {
			mcpWriteHTTPError(w, http.StatusNotAcceptable, nil, mcpErrorInvalidRequest, "not acceptable", nil)
			return r, false
		}
		headers, ok := parseMCPRequestHeaders(w, r)
		if !ok {
			return r, false
		}
		return requestWithMCPHeaders(r, headers), true
	}
	return r, true
}

func credentialDispatchMiddleware(next http.Handler, cfg config.AuthConfig, options SecurityOptions) http.Handler {
	sessionHandler := next
	csrfSessionHandler := next
	if cfg.Mode == config.AuthModeNative && options.Auth != nil {
		sessionHandler = options.Auth.SessionMiddleware(next)
		csrfSessionHandler = csrfMiddleware(sessionHandler, cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := classifyCredentialRoute(r, options.MCPEnabled)
		if route == credentialRouteNone {
			next.ServeHTTP(w, r)
			return
		}
		authHeader, authPresent, malformedAuthorization := bearerCredential(r)
		sessionPresent := hasSessionCookie(r, cfg)
		if cfg.Mode != config.AuthModeNative {
			if authPresent || malformedAuthorization {
				writeError(w, http.StatusBadRequest, "invalid_request", "authorization header is not supported")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if sessionPresent && (authPresent || malformedAuthorization) {
			writeError(w, http.StatusBadRequest, "invalid_request", "multiple authentication credentials are not permitted")
			return
		}
		switch route {
		case credentialRouteSessionOnly:
			if authPresent || malformedAuthorization {
				writeError(w, http.StatusUnauthorized, "unauthorized", "request could not be authenticated")
				return
			}
			handlerForSessionRequest(sessionHandler, csrfSessionHandler, r).ServeHTTP(w, r)
		case credentialRouteSessionFlow:
			if authPresent || malformedAuthorization {
				writeError(w, http.StatusUnauthorized, "unauthorized", "request could not be authenticated")
				return
			}
			csrfSessionHandler.ServeHTTP(w, r)
		case credentialRouteSessionOrBearer:
			if authPresent {
				actor, ok := verifyBearerCredential(w, r, options.Auth, authHeader, "", protectedResourceMetadataURL(cfg))
				if !ok {
					return
				}
				if !preflightBearerRoute(w, r, next, actor, cfg) {
					return
				}
				next.ServeHTTP(w, r.WithContext(contextWithCaller(r.Context(), actor)))
				return
			}
			if malformedAuthorization {
				writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "", protectedResourceMetadataURL(cfg))
				return
			}
			if !sessionPresent {
				writeBearerChallenge(w, http.StatusUnauthorized, "", bearerRouteRequiredScope(r), protectedResourceMetadataURL(cfg))
				return
			}
			handlerForSessionRequest(sessionHandler, csrfSessionHandler, r).ServeHTTP(w, r)
		case credentialRouteMCPBearer:
			if sessionPresent {
				writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "", protectedResourceMetadataURL(cfg))
				return
			}
			if !authPresent {
				if malformedAuthorization {
					writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "", protectedResourceMetadataURL(cfg))
				} else {
					headers, _ := mcpHeadersFromRequest(r)
					writeBearerChallenge(w, http.StatusUnauthorized, "", mcpHeaderRequiredScope(headers.method, headers.toolName), protectedResourceMetadataURL(cfg))
				}
				return
			}
			actor, ok := verifyBearerCredential(w, r, options.Auth, authHeader, "", protectedResourceMetadataURL(cfg))
			if !ok {
				return
			}
			if !preflightMCPBearerRoute(w, r, next, actor, cfg) {
				return
			}
			next.ServeHTTP(w, r.WithContext(contextWithCaller(r.Context(), actor)))
		}
	})
}

func bearerRouteRequiredScope(r *http.Request) string {
	switch r.URL.Path {
	case "/api/v1/profiles":
		return vaultservice.ScopeProfileRead
	case "/api/v1/attestations/verify":
		return vaultservice.ScopeAttestationVerify
	case "/api/v1/rotations":
		scope, _ := vaultservice.RequiredScope(vaultservice.OperationRotate)
		return scope
	default:
		_, operation, ok, _ := canonicalProfileOperation(r.URL)
		if !ok {
			return ""
		}
		scope, _ := vaultservice.RequiredScope(operation)
		return scope
	}
}

func preflightBearerRoute(w http.ResponseWriter, r *http.Request, next http.Handler, actor caller.Caller, cfg config.AuthConfig) bool {
	handler, ok := next.(*Handler)
	if !ok {
		// A non-Vaultsmith handler is used only by middleware unit tests. Production
		// always passes *Handler and therefore always uses the service-owned rule.
		return true
	}
	var scope string
	var err error
	switch {
	case r.URL.Path == "/api/v1/profiles":
		scope = vaultservice.ScopeProfileRead
		err = handler.preflightProfiles(r.Context(), actor)
	case r.URL.Path == "/api/v1/attestations/verify":
		scope = vaultservice.ScopeAttestationVerify
		if !actor.HasScope(scope) {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope, protectedResourceMetadataURL(cfg))
			return false
		}
		if handler.service == nil {
			writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeAttestationUnavailable), "rotation attestation service is unavailable")
			return false
		}
		err = handler.service.PreflightAttestationVerify(r.Context(), actor)
	case r.URL.Path == "/api/v1/rotations":
		scope = vaultservice.ScopeRotate
		err = handler.preflightOperation(r.Context(), actor, vaultservice.OperationRotate)
	default:
		_, operation, operationOK, _ := canonicalProfileOperation(r.URL)
		if !operationOK {
			return true
		}
		scope, _ = requiredBearerScope(operation)
		err = handler.preflightOperation(r.Context(), actor, operation)
	}
	if err == nil {
		return true
	}
	if vaultservice.HasCode(err, vaultservice.CodeForbidden) {
		writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope, protectedResourceMetadataURL(cfg))
	} else {
		writeServiceError(w, err)
	}
	return false
}

func preflightMCPBearerRoute(w http.ResponseWriter, r *http.Request, next http.Handler, actor caller.Caller, cfg config.AuthConfig) bool {
	handler, ok := next.(*Handler)
	if !ok {
		return true
	}
	headers, ok := mcpHeadersFromRequest(r)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return false
	}
	scope := mcpHeaderRequiredScope(headers.method, headers.toolName)
	if headers.method == "server/discover" || headers.method == "tools/list" {
		if actor.HasScope(vaultservice.ScopeAttestationVerify) {
			return true
		}
	}
	if scope == "" {
		return true
	}
	var err error
	if headers.method == "tools/call" && headers.toolName == "verify_rotation_attestation" {
		scope = vaultservice.ScopeAttestationVerify
		err = handler.service.PreflightAttestationVerify(r.Context(), actor)
	} else if scope == vaultservice.ScopeProfileRead {
		err = handler.preflightProfiles(r.Context(), actor)
	} else {
		operation := vaultservice.Operation(headers.toolName)
		err = handler.preflightOperation(r.Context(), actor, operation)
	}
	if err == nil {
		return true
	}
	if headers.method == "tools/call" && headers.toolName == "verify_rotation_attestation" &&
		(vaultservice.HasCode(err, vaultservice.CodeFeatureUnavailable) || vaultservice.HasCode(err, vaultservice.CodeAttestationUnavailable)) {
		return true
	}
	if vaultservice.HasCode(err, vaultservice.CodeForbidden) {
		writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope, protectedResourceMetadataURL(cfg))
	} else {
		writeServiceError(w, err)
	}
	return false
}

func handlerForSessionRequest(sessionHandler, csrfSessionHandler http.Handler, r *http.Request) http.Handler {
	if safeCSRFMethod(r.Method) {
		return sessionHandler
	}
	return csrfSessionHandler
}

type credentialRoute int

const (
	credentialRouteNone credentialRoute = iota
	credentialRouteSessionFlow
	credentialRouteSessionOnly
	credentialRouteSessionOrBearer
	credentialRouteMCPBearer
)

func classifyCredentialRoute(r *http.Request, mcpEnabled bool) credentialRoute {
	switch {
	case strings.HasPrefix(r.URL.Path, "/auth/"), r.URL.Path == "/api/v1/session":
		return credentialRouteSessionFlow
	case r.URL.Path == "/api/v1/operations":
		return credentialRouteSessionOnly
	case r.URL.Path == "/api/v1/profiles" || r.URL.Path == "/api/v1/rotations" || r.URL.Path == "/api/v1/attestations/verify" || canonicalOperationPath(r.URL):
		return credentialRouteSessionOrBearer
	case r.URL.Path == "/mcp" && mcpEnabled:
		return credentialRouteMCPBearer
	default:
		return credentialRouteNone
	}
}

func canonicalOperationPath(u *url.URL) bool {
	_, _, ok, invalid := canonicalProfileOperation(u)
	return ok || invalid
}

func bearerCredential(r *http.Request) (string, bool, bool) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", false, false
	}
	if len(values) != 1 {
		return "", false, true
	}
	value := strings.TrimSpace(values[0])
	scheme, token, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" || strings.Contains(token, " ") || strings.Contains(value, ",") {
		return "", false, true
	}
	return token, true, false
}

func hasSessionCookie(r *http.Request, cfg config.AuthConfig) bool {
	cookieName := strings.TrimSpace(cfg.Session.CookieName)
	if cookieName == "" {
		return false
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == cookieName && cookie.Value != "" {
			return true
		}
	}
	return false
}

func verifyBearerCredential(w http.ResponseWriter, r *http.Request, auth *authn.Authenticator, token, requiredScope, resourceMetadataURL string) (caller.Caller, bool) {
	if auth == nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return caller.Caller{}, false
	}
	actor, err := auth.VerifyAccessToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, authn.ErrAccessTokenKeyUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
			return caller.Caller{}, false
		}
		writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "", resourceMetadataURL)
		return caller.Caller{}, false
	}
	if requiredScope != "" && !actor.HasScope(requiredScope) {
		writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", requiredScope, resourceMetadataURL)
		return caller.Caller{}, false
	}
	return actor, true
}

const nativeCSRFCookieName = "__Host-vaultsmith_csrf"

func csrfCookieName(cfg config.AuthConfig) string {
	if cfg.Mode == config.AuthModeNative {
		return nativeCSRFCookieName
	}
	return "vaultsmith_csrf"
}

func corsMiddleware(next http.Handler, cfg config.AuthConfig, mcpEnabled bool) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.CORS.AllowedOrigins))
	for _, origin := range cfg.CORS.AllowedOrigins {
		if key, ok := originComparisonKey(origin, true); ok {
			allowed[key] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if origin == "null" {
			writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
			return
		}
		originKey, originKeyOK := originComparisonKey(origin, false)
		_, explicitlyAllowed := allowed[originKey]
		if !originKeyOK {
			explicitlyAllowed = false
		}
		originAllowed := originAllowed(origin, r, cfg)
		if !explicitlyAllowed && !originAllowed {
			writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
			return
		}
		if explicitlyAllowed || originAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", corsAllowedHeaders(r, cfg, mcpEnabled))
			w.Header().Set("Access-Control-Allow-Methods", corsAllowedMethods(r, mcpEnabled))
			w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, X-Request-ID, Retry-After")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if r.URL.Path == "/mcp" && !mcpEnabled {
				writeError(w, http.StatusNotFound, "not_found", "resource was not found")
				return
			}
			if r.URL.Path == "/mcp" && !validMCPPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originAllowed(origin string, r *http.Request, cfg config.AuthConfig) bool {
	return isSameOrigin(origin, r, cfg)
}

func corsAllowedHeaders(r *http.Request, cfg config.AuthConfig, mcpEnabled bool) string {
	headers := []string{"Content-Type", "X-CSRF-Token"}
	if r.URL.Path == "/mcp" && mcpEnabled {
		headers = append(headers, "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name")
		if cfg.Mode == config.AuthModeNative {
			headers = append(headers, "Authorization")
		}
	} else if cfg.Mode == config.AuthModeNative {
		if r.URL.Path == "/api/v1/profiles" || r.URL.Path == "/api/v1/rotations" || r.URL.Path == "/api/v1/attestations/verify" || canonicalOperationPath(r.URL) {
			headers = append(headers, "Authorization")
		}
	}
	return strings.Join(headers, ", ")
}

func corsAllowedMethods(r *http.Request, mcpEnabled bool) string {
	if r.URL.Path == "/mcp" && mcpEnabled {
		return "POST, OPTIONS"
	}
	return "GET, POST, OPTIONS"
}

func isSameOrigin(origin string, r *http.Request, cfg config.AuthConfig) bool {
	originKey, ok := originComparisonKey(origin, false)
	if !ok {
		return false
	}
	expected := requestOrigin(r)
	if cfg.OIDC.PublicBaseURL != "" {
		expected = cfg.OIDC.PublicBaseURL
	}
	expectedKey, ok := originComparisonKey(expected, true)
	if !ok {
		return false
	}
	return originKey == expectedKey
}

func originComparisonKey(raw string, allowRootPath bool) (string, bool) {
	if strings.ContainsAny(raw, "?#") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", false
	}
	if parsed.Path != "" && (!allowRootPath || parsed.Path != "/") {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	return scheme + "|" + host + "|" + port, true
}

func requestOrigin(r *http.Request) string {
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if proto == "" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	return proto + "://" + r.Host
}

func (h *Handler) requestCaller(r *http.Request) (caller.Caller, bool, int, string) {
	if actor, ok := callerFromContext(r.Context()); ok {
		return actor, true, 0, ""
	}
	if h.authConfig.Mode != config.AuthModeNative {
		return caller.Anonymous(), true, 0, ""
	}
	if h.auth == nil {
		return caller.Caller{}, false, http.StatusServiceUnavailable, "not_ready"
	}
	principal, found, err := h.auth.AuthenticatedPrincipal(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, authn.ErrNotAuthenticated), errors.Is(err, authn.ErrRefreshRequired):
			return caller.Caller{}, false, http.StatusUnauthorized, "unauthorized"
		case errors.Is(err, authn.ErrTemporaryUnavailable):
			return caller.Caller{}, false, http.StatusServiceUnavailable, "temporarily_unavailable"
		default:
			return caller.Caller{}, false, http.StatusUnauthorized, "unauthorized"
		}
	}
	if !found {
		return caller.Caller{}, false, http.StatusUnauthorized, "unauthorized"
	}
	actor, err := caller.NewSession(principal.Issuer, principal.Subject, principal.Groups)
	if err != nil {
		return caller.Caller{}, false, http.StatusServiceUnavailable, "not_ready"
	}
	return actor, true, 0, ""
}

type callerContextKey struct{}

func contextWithCaller(ctx context.Context, actor caller.Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, actor)
}

func callerFromContext(ctx context.Context) (caller.Caller, bool) {
	actor, ok := ctx.Value(callerContextKey{}).(caller.Caller)
	if !ok {
		return caller.Caller{}, false
	}
	return actor, true
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	message := "request could not be authenticated"
	if status == http.StatusServiceUnavailable {
		message = "service is temporarily unavailable"
	}
	writeError(w, status, code, message)
}

func protectedResourceMetadataURL(cfg config.AuthConfig) string {
	base := strings.TrimRight(strings.TrimSpace(cfg.OIDC.PublicBaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/.well-known/oauth-protected-resource"
}

func writeBearerChallenge(w http.ResponseWriter, status int, bearerError, scope, resourceMetadataURL string) {
	w.Header().Set("WWW-Authenticate", bearerChallenge(bearerError, scope, resourceMetadataURL))
	code := "unauthorized"
	message := "request could not be authenticated"
	if status == http.StatusForbidden {
		code = "forbidden"
		message = "operation is not permitted"
	}
	writeError(w, status, code, message)
}

func bearerChallenge(bearerError, scope, resourceMetadataURL string) string {
	parts := []string{`Bearer realm="vaultsmith"`}
	if bearerError != "" {
		parts = append(parts, `error="`+bearerError+`"`)
	}
	if scope != "" {
		parts = append(parts, `scope="`+scope+`"`)
	}
	if resourceMetadataURL != "" {
		parts = append(parts, `resource_metadata="`+resourceMetadataURL+`"`)
	}
	return strings.Join(parts, ", ")
}

func authURLReturnTo(r *http.Request) string {
	value := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if value == "" {
		return "/"
	}
	return value
}
