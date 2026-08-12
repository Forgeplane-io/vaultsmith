package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
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
	Encrypt bool `json:"encrypt"`
	Decrypt bool `json:"decrypt"`
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

type profilesResponse struct {
	Profiles []Profile `json:"profiles"`
}

type valueResponse struct {
	Value string `json:"value"`
}

type statusResponse struct {
	Status string `json:"status"`
}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	AuthRequired  bool   `json:"authRequired"`
	Email         string `json:"email,omitempty"`
	CSRFToken     string `json:"csrfToken"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/profiles":
		h.serveProfiles(w, r)
	case "/api/v1/operations":
		h.serveOperation(w, r)
	case "/api/v1/session":
		h.serveSession(w, r)
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
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
	}
}

func (h *Handler) serveProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.rejectUnsupportedAuthorization(w, r) {
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	profiles, err := h.service.ListProfiles(r.Context(), actor)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	public := make([]Profile, 0, len(profiles))
	for _, profile := range profiles {
		public = append(public, Profile{
			ID:    profile.ID,
			Label: profile.Label,
			Capabilities: ProfileCapabilities{
				Encrypt: profile.Capabilities.Encrypt,
				Decrypt: profile.Capabilities.Decrypt,
			},
		})
	}
	writeJSON(w, http.StatusOK, profilesResponse{Profiles: public})
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
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
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

func decodeStrictOperationObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("request must be a JSON object")
	}
	fields := make(map[string]json.RawMessage, 5)
	seen := make(map[string]struct{}, 5)
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
		switch key {
		case "profileId", "sourceProfileId", "destinationProfileId", "mode", "value":
		default:
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}
