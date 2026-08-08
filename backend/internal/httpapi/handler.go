package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

const (
	MaxPlaintextBytes   = ansiblevault.MaxPlaintextBytes
	MaxVaultTextBytes   = 5 << 20
	MaxRequestBodyBytes = 8 << 20
)

type Profile struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Executor interface {
	Execute(profileID, mode, value string) (string, error)
	Rotate(sourceProfileID, destinationProfileID, value string) (string, error)
}

type Handler struct {
	profiles   map[string]struct{}
	public     []Profile
	executor   Executor
	ready      bool
	auth       *authn.Authenticator
	authorizer *authz.Authorizer
	authConfig config.AuthConfig
}

type operationRequest struct {
	ProfileID            string `json:"profileId"`
	SourceProfileID      string `json:"sourceProfileId"`
	DestinationProfileID string `json:"destinationProfileId"`
	Mode                 string `json:"mode"`
	Value                string `json:"value"`
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

func newHandler(profiles []Profile, executor Executor) *Handler {
	public := make([]Profile, 0, len(profiles))
	profileSet := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		public = append(public, profile)
		profileSet[profile.ID] = struct{}{}
	}
	return &Handler{
		profiles: profileSet,
		public:   public,
		executor: executor,
		ready:    len(public) > 0 && executor != nil,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
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
	if h.authConfig.Mode == config.AuthModeNative {
		principal, ok, status, code := h.requirePrincipal(r)
		if !ok {
			writeAuthError(w, status, code)
			return
		}
		allowedIDs := h.authorizer.FilterProfiles(principal, profileIDs(h.public))
		allowed := make(map[string]struct{}, len(allowedIDs))
		for _, id := range allowedIDs {
			allowed[id] = struct{}{}
		}
		filtered := make([]Profile, 0, len(allowedIDs))
		for _, profile := range h.public {
			if _, exists := allowed[profile.ID]; exists {
				filtered = append(filtered, profile)
			}
		}
		writeJSON(w, http.StatusOK, profilesResponse{Profiles: filtered})
		return
	}
	writeJSON(w, http.StatusOK, profilesResponse{Profiles: h.public})
}

func profileIDs(profiles []Profile) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

func (h *Handler) serveOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	request, err := decodeOperation(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		}
		return
	}
	if request.Mode != "encrypt" && request.Mode != "decrypt" && request.Mode != "rotate" {
		writeError(w, http.StatusBadRequest, "invalid_request", "operation mode is invalid")
		return
	}
	var principal authn.Principal
	if h.authConfig.Mode == config.AuthModeNative {
		var authenticated bool
		var status int
		var code string
		principal, authenticated, status, code = h.requirePrincipal(r)
		if !authenticated {
			writeAuthError(w, status, code)
			return
		}
	}
	if request.Mode == "rotate" {
		if request.ProfileID != "" || request.SourceProfileID == "" || request.DestinationProfileID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "rotate requires source and destination profiles")
			return
		}
		if _, ok := h.profiles[request.SourceProfileID]; !ok {
			writeProfileAccessError(w, h.authConfig.Mode)
			return
		}
		if _, ok := h.profiles[request.DestinationProfileID]; !ok {
			writeProfileAccessError(w, h.authConfig.Mode)
			return
		}
	} else {
		if request.SourceProfileID != "" || request.DestinationProfileID != "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "source and destination profiles are only valid for rotate")
			return
		}
		if _, ok := h.profiles[request.ProfileID]; !ok {
			writeProfileAccessError(w, h.authConfig.Mode)
			return
		}
	}
	if !utf8.ValidString(request.Value) {
		writeError(w, http.StatusBadRequest, "invalid_request", "value must be valid UTF-8")
		return
	}
	valueBytes := len([]byte(request.Value))
	maxValueBytes := MaxPlaintextBytes
	if request.Mode != "encrypt" {
		maxValueBytes = MaxVaultTextBytes
	}
	if valueBytes > maxValueBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "value is too large")
		return
	}
	if h.authConfig.Mode == config.AuthModeNative {
		var authErr error
		if request.Mode == "rotate" {
			authErr = h.authorizer.AuthorizeRotate(principal, request.SourceProfileID, request.DestinationProfileID)
		} else {
			action := authz.ActionEncrypt
			if request.Mode == "decrypt" {
				action = authz.ActionDecrypt
			}
			authErr = h.authorizer.Authorize(principal, action, authz.ProfileResource(request.ProfileID))
		}
		if authErr != nil {
			if errors.Is(authErr, authz.ErrForbidden) {
				writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
			} else {
				writeError(w, http.StatusServiceUnavailable, "not_ready", "authorization is not ready")
			}
			return
		}
	}
	if h.executor == nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}
	var output string
	if request.Mode == "rotate" {
		output, err = h.executor.Rotate(request.SourceProfileID, request.DestinationProfileID, request.Value)
	} else {
		output, err = h.executor.Execute(request.ProfileID, request.Mode, request.Value)
	}
	if err != nil || !utf8.ValidString(output) {
		writeError(w, http.StatusUnprocessableEntity, "operation_failed", "vault operation failed")
		return
	}
	writeJSON(w, http.StatusOK, valueResponse{Value: output})
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
	if !h.ready {
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ready"})
}

var errBodyTooLarge = errors.New("request body too large")

func decodeOperation(w http.ResponseWriter, r *http.Request) (operationRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request operationRequest
	if err := decoder.Decode(&request); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return operationRequest{}, errBodyTooLarge
		}
		return operationRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return operationRequest{}, errBodyTooLarge
		}
		return operationRequest{}, errors.New("trailing JSON")
	}
	return request, nil
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

func writeProfileAccessError(w http.ResponseWriter, mode config.AuthMode) {
	if mode == config.AuthModeNative {
		writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "profile was not found")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}
