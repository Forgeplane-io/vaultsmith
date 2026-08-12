package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

const (
	MaxPlaintextBytes   = vaultservice.MaxPlaintextBytes
	MaxVaultTextBytes   = vaultservice.MaxVaultTextBytes
	MaxRequestBodyBytes = 8 << 20
)

type Profile struct {
	ID           string              `json:"id"`
	Label        string              `json:"label"`
	Capabilities ProfileCapabilities `json:"capabilities"`
}

type ProfileCapabilities struct {
	Encrypt           bool `json:"encrypt"`
	Decrypt           bool `json:"decrypt"`
	RotateSource      bool `json:"rotateSource"`
	RotateDestination bool `json:"rotateDestination"`
}

type Executor = vaultservice.Executor

type Handler struct {
	service    *vaultservice.Service
	auth       *authn.Authenticator
	authConfig config.AuthConfig
}

type operationRequest struct {
	ProfileID            string
	SourceProfileID      string
	DestinationProfileID string
	Mode                 string
	Value                string
	present              map[string]bool
}

type profilesResponse = apimodels.ProfilesResponse
type valueResponse = apimodels.LegacyValueResponse
type encryptResponse = apimodels.EncryptResponse
type decryptResponse = apimodels.DecryptResponse
type rotateResponse = apimodels.RotateResponse

type statusResponse struct {
	Status string `json:"status"`
}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	AuthRequired  bool   `json:"authRequired"`
	Email         string `json:"email,omitempty"`
	CSRFToken     string `json:"csrfToken"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ensureRequestID(w)
	switch r.URL.Path {
	case "/api/v1/profiles":
		h.serveProfiles(w, r)
	case "/api/v1/operations":
		h.serveOperation(w, r)
	case "/api/v1/rotations":
		h.serveCanonicalRotate(w, r)
	case "/api/v1/session":
		h.serveSession(w, r)
	case "/.well-known/oauth-protected-resource":
		h.serveProtectedResourceMetadata(w, r)
	case "/metrics":
		h.serveMetrics(w, r)
	case "/mcp":
		h.serveMCP(w, r)
	case "/auth/login":
		h.serveLogin(w, r)
	case "/auth/callback":
		h.serveCallback(w, r)
	case "/auth/logout":
		h.serveLogout(w, r)
	case "/healthz":
		h.serveHealth(w, r)
	case "/readyz":
		h.serveReady(w, r)
	default:
		if profileID, operation, ok, invalid := canonicalProfileOperation(r.URL); ok || invalid {
			if invalid {
				writeError(w, http.StatusBadRequest, "invalid_request", "profile ID is invalid")
				return
			}
			switch operation {
			case vaultservice.OperationEncrypt:
				h.serveCanonicalEncrypt(w, r, profileID)
			case vaultservice.OperationDecrypt:
				h.serveCanonicalDecrypt(w, r, profileID)
			default:
				writeError(w, http.StatusNotFound, "not_found", "resource was not found")
			}
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
	}
}

func (h *Handler) preflightProfiles(ctx context.Context, actor caller.Caller) error {
	return h.service.PreflightProfiles(ctx, actor)
}

func (h *Handler) preflightOperation(ctx context.Context, actor caller.Caller, operation vaultservice.Operation) error {
	return h.service.Preflight(ctx, actor, operation)
}

func (h *Handler) serveProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	if err := h.preflightProfiles(r.Context(), actor); err != nil {
		if actor.Kind() == caller.KindBearer && vaultservice.HasCode(err, vaultservice.CodeForbidden) {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeProfileRead)
		} else {
			writeServiceError(w, err)
		}
		return
	}
	profiles, err := h.service.ListProfiles(r.Context(), actor)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	public := make([]apimodels.Profile, 0, len(profiles))
	for _, profile := range profiles {
		public = append(public, apimodels.Profile{
			Id:    profile.ID,
			Label: profile.Label,
			Capabilities: apimodels.ProfileCapabilities{
				Encrypt:           profile.Capabilities.Encrypt,
				Decrypt:           profile.Capabilities.Decrypt,
				RotateSource:      profile.Capabilities.RotateSource,
				RotateDestination: profile.Capabilities.RotateDestination,
			},
		})
	}
	writeJSON(w, http.StatusOK, profilesResponse{Profiles: public})
}

func (h *Handler) serveCanonicalEncrypt(w http.ResponseWriter, r *http.Request, profileID string) {
	h.serveCanonicalOperation(w, r, vaultservice.OperationEncrypt, func(fields map[string]string) (vaultservice.Command, error) {
		plaintext, ok := fields["plaintext"]
		if !ok {
			return vaultservice.Command{}, errors.New("required request field is missing")
		}
		request := apimodels.EncryptRequest{Plaintext: plaintext}
		return vaultservice.Command{Operation: vaultservice.OperationEncrypt, ProfileID: profileID, Value: request.Plaintext}, nil
	}, func(output string) any {
		return encryptResponse{VaultText: output}
	})
}

func (h *Handler) serveCanonicalDecrypt(w http.ResponseWriter, r *http.Request, profileID string) {
	h.serveCanonicalOperation(w, r, vaultservice.OperationDecrypt, func(fields map[string]string) (vaultservice.Command, error) {
		vaultText, ok := fields["vaultText"]
		if !ok {
			return vaultservice.Command{}, errors.New("required request field is missing")
		}
		request := apimodels.DecryptRequest{VaultText: vaultText}
		return vaultservice.Command{Operation: vaultservice.OperationDecrypt, ProfileID: profileID, Value: request.VaultText}, nil
	}, func(output string) any {
		return decryptResponse{Plaintext: output}
	})
}

func (h *Handler) serveCanonicalRotate(w http.ResponseWriter, r *http.Request) {
	h.serveCanonicalOperation(w, r, vaultservice.OperationRotate, func(fields map[string]string) (vaultservice.Command, error) {
		source, sourceOK := fields["sourceProfileId"]
		destination, destinationOK := fields["destinationProfileId"]
		vaultText, vaultOK := fields["vaultText"]
		if !sourceOK || !destinationOK || !vaultOK {
			return vaultservice.Command{}, errors.New("required request field is missing")
		}
		request := apimodels.RotateRequest{SourceProfileId: source, DestinationProfileId: destination, VaultText: vaultText}
		return vaultservice.Command{Operation: vaultservice.OperationRotate, SourceProfileID: request.SourceProfileId, DestinationProfileID: request.DestinationProfileId, Value: request.VaultText}, nil
	}, func(output string) any {
		return rotateResponse{VaultText: output}
	})
}

type canonicalCommandDecoder func(map[string]string) (vaultservice.Command, error)
type canonicalResponseBuilder func(string) any

func (h *Handler) serveCanonicalOperation(w http.ResponseWriter, r *http.Request, operation vaultservice.Operation, decodeCommand canonicalCommandDecoder, response canonicalResponseBuilder) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	if err := h.preflightOperation(r.Context(), actor, operation); err != nil {
		if actor.Kind() == caller.KindBearer && vaultservice.HasCode(err, vaultservice.CodeForbidden) {
			scope, _ := requiredBearerScope(operation)
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope)
		} else {
			writeServiceError(w, err)
		}
		return
	}
	lease, err := h.service.Admission().TryAcquire(r.Context())
	if err != nil {
		if errors.Is(err, vaultservice.ErrAdmissionSaturated) {
			writeAdmissionSaturated(w, h.service.Admission())
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeServiceError(w, err)
		}
		return
	}
	defer lease.Release()
	leaseContext := lease.Context(r.Context())

	fields, err := decodeStrictStringFields(w, r, canonicalAllowedFields(operation))
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		}
		return
	}
	command, err := decodeCommand(fields)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	prepared, err := h.service.Prepare(leaseContext, actor, command, lease)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	output, err := prepared.Run(leaseContext)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response(output))
}

func (h *Handler) serveOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if h.rejectUnsupportedAuthorization(w, r) {
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	lease, err := h.service.Admission().TryAcquire(r.Context())
	if err != nil {
		if errors.Is(err, vaultservice.ErrAdmissionSaturated) {
			writeAdmissionSaturated(w, h.service.Admission())
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeServiceError(w, err)
		}
		return
	}
	defer lease.Release()
	leaseContext := lease.Context(r.Context())

	request, err := decodeOperation(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		}
		return
	}
	prepared, err := h.service.Prepare(leaseContext, actor, request.command(), lease)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	output, err := prepared.Run(leaseContext)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, valueResponse{Value: output})
}

func canonicalAllowedFields(operation vaultservice.Operation) map[string]struct{} {
	switch operation {
	case vaultservice.OperationEncrypt:
		return map[string]struct{}{"plaintext": {}}
	case vaultservice.OperationDecrypt:
		return map[string]struct{}{"vaultText": {}}
	case vaultservice.OperationRotate:
		return map[string]struct{}{"sourceProfileId": {}, "destinationProfileId": {}, "vaultText": {}}
	default:
		return nil
	}
}

func canonicalProfileOperation(u *url.URL) (string, vaultservice.Operation, bool, bool) {
	escaped := u.EscapedPath()
	const prefix = "/api/v1/profiles/"
	if !strings.HasPrefix(escaped, prefix) {
		return "", "", false, false
	}
	rest := strings.TrimPrefix(escaped, prefix)
	var suffix string
	var operation vaultservice.Operation
	switch {
	case strings.HasSuffix(rest, "/encrypt"):
		suffix = "/encrypt"
		operation = vaultservice.OperationEncrypt
	case strings.HasSuffix(rest, "/decrypt"):
		suffix = "/decrypt"
		operation = vaultservice.OperationDecrypt
	default:
		return "", "", false, false
	}
	escapedProfileID := strings.TrimSuffix(rest, suffix)
	if escapedProfileID == "" || containsEscapedPathSeparator(escapedProfileID) {
		return "", "", false, true
	}
	profileID, err := url.PathUnescape(escapedProfileID)
	if err != nil || strings.Contains(profileID, "/") || !config.IsValidProfileID(profileID) {
		return "", "", false, true
	}
	return profileID, operation, true, false
}

func containsEscapedPathSeparator(value string) bool {
	lowered := strings.ToLower(value)
	return strings.Contains(lowered, "%2f") || strings.Contains(lowered, "%5c")
}

func (r operationRequest) command() vaultservice.Command {
	return vaultservice.Command{
		Operation:            vaultservice.Operation(r.Mode),
		ProfileID:            r.ProfileID,
		SourceProfileID:      r.SourceProfileID,
		DestinationProfileID: r.DestinationProfileID,
		Value:                r.Value,
	}
}

func (h *Handler) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) serveReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.service == nil || !h.service.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ready"})
}

type protectedResourceMetadataResponse struct {
	Resource                 string   `json:"resource"`
	AuthorizationServers     []string `json:"authorization_servers"`
	ScopesSupported          []string `json:"scopes_supported"`
	BearerMethodsSupported   []string `json:"bearer_methods_supported"`
	ResourceSigningAlgValues []string `json:"resource_signing_alg_values_supported,omitempty"`
}

func (h *Handler) serveProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.authConfig.Mode != config.AuthModeNative {
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
		return
	}
	ensureRequestID(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(protectedResourceMetadataResponse{
		Resource:               h.authConfig.OIDC.PublicBaseURL,
		AuthorizationServers:   []string{h.authConfig.OIDC.IssuerURL},
		ScopesSupported:        []string{vaultservice.ScopeProfileRead, vaultservice.ScopeEncrypt, vaultservice.ScopeDecrypt, vaultservice.ScopeRotate},
		BearerMethodsSupported: []string{"header"},
	})
}

func (h *Handler) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	admission := h.service.Admission()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	ensureRequestID(w)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "vaultsmith_operation_admission_capacity %d\n", admission.Capacity())
	_, _ = fmt.Fprintf(w, "vaultsmith_operation_admission_in_use %d\n", admission.InUse())
	_, _ = fmt.Fprintf(w, "vaultsmith_operation_admission_rejections_total %d\n", admission.Rejections())
}

var errBodyTooLarge = errors.New("request body too large")

func decodeOperation(w http.ResponseWriter, r *http.Request) (operationRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return operationRequest{}, errBodyTooLarge
		}
		return operationRequest{}, err
	}
	validUTF8 := utf8.Valid(raw)
	if contextErr := r.Context().Err(); contextErr != nil {
		return operationRequest{}, contextErr
	}
	if !validUTF8 {
		return operationRequest{}, errors.New("request is not valid UTF-8")
	}
	fields, decodeErr := decodeStrictOperationObject(raw)
	if contextErr := r.Context().Err(); contextErr != nil {
		return operationRequest{}, contextErr
	}
	if decodeErr != nil {
		return operationRequest{}, decodeErr
	}
	request := operationRequest{present: make(map[string]bool, len(fields))}
	for key, value := range fields {
		decoded, decodeErr := decodeOperationString(value)
		if contextErr := r.Context().Err(); contextErr != nil {
			return operationRequest{}, contextErr
		}
		if decodeErr != nil {
			return operationRequest{}, decodeErr
		}
		request.present[key] = true
		switch key {
		case "profileId":
			request.ProfileID = decoded
		case "sourceProfileId":
			request.SourceProfileID = decoded
		case "destinationProfileId":
			request.DestinationProfileID = decoded
		case "mode":
			request.Mode = decoded
		case "value":
			request.Value = decoded
		}
	}
	shapeErr := request.validateShape()
	if contextErr := r.Context().Err(); contextErr != nil {
		return operationRequest{}, contextErr
	}
	if shapeErr != nil {
		return operationRequest{}, shapeErr
	}
	return request, nil
}

func readRequestBody(ctx context.Context, body io.ReadCloser) ([]byte, error) {
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = body.Close()
		case <-stop:
		}
	}()

	raw, err := io.ReadAll(body)
	close(stop)
	<-stopped
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	return raw, err
}

func decodeStrictStringFields(w http.ResponseWriter, r *http.Request, allowed map[string]struct{}) (map[string]string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	validUTF8 := utf8.Valid(raw)
	if contextErr := r.Context().Err(); contextErr != nil {
		return nil, contextErr
	}
	if !validUTF8 {
		return nil, errors.New("request is not valid UTF-8")
	}
	fields, decodeErr := decodeStrictObject(raw, allowed)
	if contextErr := r.Context().Err(); contextErr != nil {
		return nil, contextErr
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	values := make(map[string]string, len(fields))
	for key, value := range fields {
		decoded, decodeErr := decodeOperationString(value)
		if contextErr := r.Context().Err(); contextErr != nil {
			return nil, contextErr
		}
		if decodeErr != nil {
			return nil, decodeErr
		}
		values[key] = decoded
	}
	return values, nil
}

func decodeStrictObject(raw []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("request must be a JSON object")
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("request field name is invalid")
		}
		folded := strings.ToLower(key)
		if _, duplicate := seen[folded]; duplicate {
			return nil, errors.New("duplicate request field")
		}
		seen[folded] = struct{}{}
		if _, ok := allowed[key]; !ok {
			return nil, errors.New("unknown request field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	last, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := last.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("request object is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}

func decodeStrictOperationObject(raw []byte) (map[string]json.RawMessage, error) {
	return decodeStrictObject(raw, map[string]struct{}{
		"profileId":            {},
		"sourceProfileId":      {},
		"destinationProfileId": {},
		"mode":                 {},
		"value":                {},
	})
}

func decodeOperationString(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", errors.New("request field must be a string")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errors.New("request field must be a string")
	}
	return value, nil
}

func (r operationRequest) validateShape() error {
	if !r.present["mode"] || !r.present["value"] {
		return errors.New("required request field is missing")
	}
	switch r.Mode {
	case string(vaultservice.OperationEncrypt), string(vaultservice.OperationDecrypt):
		if !r.present["profileId"] || r.present["sourceProfileId"] || r.present["destinationProfileId"] {
			return errors.New("operation fields are invalid")
		}
	case string(vaultservice.OperationRotate):
		if r.present["profileId"] || !r.present["sourceProfileId"] || !r.present["destinationProfileId"] {
			return errors.New("operation fields are invalid")
		}
	default:
		// The service owns operation semantics and returns the stable domain error.
		return nil
	}
	return nil
}

func (h *Handler) rejectUnsupportedAuthorization(w http.ResponseWriter, r *http.Request) bool {
	return rejectUnsupportedAuthorization(w, r, h.authConfig)
}

func rejectUnsupportedAuthorization(w http.ResponseWriter, r *http.Request, authConfig config.AuthConfig) bool {
	if !hasUnsupportedAuthorization(r) {
		return false
	}
	if authConfig.Mode != config.AuthModeNative {
		writeError(w, http.StatusBadRequest, "invalid_request", "authorization header is not supported")
		return true
	}
	cookieName := strings.TrimSpace(authConfig.Session.CookieName)
	if cookieName != "" {
		for _, cookie := range r.Cookies() {
			if cookie.Name == cookieName && cookie.Value != "" {
				writeError(w, http.StatusBadRequest, "invalid_request", "multiple authentication credentials are not permitted")
				return true
			}
		}
	}
	writeError(w, http.StatusUnauthorized, "unauthorized", "request could not be authenticated")
	return true
}

func hasUnsupportedAuthorization(r *http.Request) bool {
	return len(r.Header.Values("Authorization")) > 0
}

func supportsIdentityContentEncoding(header http.Header) bool {
	values := header.Values("Content-Encoding")
	if len(values) == 0 {
		return true
	}
	codings := 0
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			coding := strings.TrimSpace(part)
			if coding == "" || !strings.EqualFold(coding, "identity") {
				return false
			}
			codings++
			if codings > 1 {
				return false
			}
		}
	}
	return codings == 1
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'")
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed")
}

func writeServiceError(w http.ResponseWriter, err error) {
	var domain *vaultservice.Error
	if !errors.As(err, &domain) {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}
	status := http.StatusServiceUnavailable
	code := string(domain.Code())
	switch domain.Code() {
	case vaultservice.CodeInvalidRequest:
		status = http.StatusBadRequest
	case vaultservice.CodeTooLarge:
		status = http.StatusRequestEntityTooLarge
		code = "invalid_request"
	case vaultservice.CodeNotFound:
		status = http.StatusNotFound
	case vaultservice.CodeForbidden:
		status = http.StatusForbidden
	case vaultservice.CodeNotReady:
		status = http.StatusServiceUnavailable
	case vaultservice.CodeOperationFailed:
		status = http.StatusUnprocessableEntity
	case vaultservice.CodeTemporarilyUnavailable:
		status = http.StatusServiceUnavailable
	default:
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}
	writeError(w, status, code, domain.SafeMessage())
}

func requiredBearerScope(operation vaultservice.Operation) (string, bool) {
	return vaultservice.RequiredScope(operation)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	ensureRequestID(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apimodels.ErrorResponse{Error: apimodels.ApiError{Code: apimodels.ApiErrorCode(code), Message: message}})
}

func ensureRequestID(w http.ResponseWriter) {
	if w.Header().Get("X-Request-ID") != "" {
		return
	}
	w.Header().Set("X-Request-ID", newRequestID())
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(value[:])
}
