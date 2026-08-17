package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/forgeplane-io/vaultsmith/backend/internal/version"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpProtocolVersion    = "2026-07-28"
	maxMCPVerifyBodyBytes = maxAttestationVerifyBodyBytes

	mcpErrorParse                 = -32700
	mcpErrorInvalidRequest        = -32600
	mcpErrorMethodNotFound        = -32601
	mcpErrorInvalidParams         = -32602
	mcpErrorHeaderMismatch        = -32020
	mcpErrorUnsupportedProtocol   = -32022
	mcpTextToolFailure            = "tool call failed"
	mcpTextInvalidToolArguments   = "tool arguments are invalid"
	mcpContentTypeApplicationJSON = "application/json"
	mcpContentTypeEventStream     = "text/event-stream"
)

type mcpJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Result  any              `json:"result,omitempty"`
	Error   *mcpJSONRPCError `json:"error,omitempty"`
}

type mcpJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpDiscoverResult struct {
	Meta              mcp.Meta                `json:"_meta"`
	ResultType        string                  `json:"resultType"`
	TTLMs             int                     `json:"ttlMs"`
	CacheScope        string                  `json:"cacheScope"`
	SupportedVersions []string                `json:"supportedVersions"`
	Capabilities      *mcp.ServerCapabilities `json:"capabilities"`
}

type mcpListToolsResult struct {
	Meta       mcp.Meta    `json:"_meta"`
	ResultType string      `json:"resultType"`
	TTLMs      int         `json:"ttlMs"`
	CacheScope string      `json:"cacheScope"`
	Tools      []*mcp.Tool `json:"tools"`
	NextCursor string      `json:"nextCursor,omitempty"`
}

type mcpCallToolResult struct {
	Meta              mcp.Meta      `json:"_meta"`
	ResultType        string        `json:"resultType"`
	TTLMs             int           `json:"ttlMs"`
	CacheScope        string        `json:"cacheScope"`
	Content           []mcp.Content `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError"`
}

func (h *Handler) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		mcpWriteHTTPError(w, http.StatusUnsupportedMediaType, nil, mcpErrorInvalidRequest, "unsupported media type", nil)
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		mcpWriteHTTPError(w, http.StatusUnsupportedMediaType, nil, mcpErrorInvalidRequest, "unsupported media type", nil)
		return
	}
	if !mcpAccepts(r.Header.Values("Accept")) {
		mcpWriteHTTPError(w, http.StatusNotAcceptable, nil, mcpErrorInvalidRequest, "not acceptable", nil)
		return
	}
	headers, ok := mcpHeadersFromRequest(r)
	if !ok {
		headers, ok = parseMCPRequestHeaders(w, r)
		if !ok {
			return
		}
	}
	headerVersion := headers.protocolVersion
	headerMethod := headers.method
	headerToolName := headers.toolName

	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	verifyCall := headerMethod == "tools/call" && headerToolName == "verify_rotation_attestation"
	generateCall := headerMethod == "tools/call" && isMCPGenerateTool(headerToolName)
	var verifyPreflightErr error
	if generateCall {
		generatePreflightErr := h.service.PreflightGenerate(r.Context(), actor)
		if generatePreflightErr != nil {
			if actor.Kind() == caller.KindBearer && vaultservice.HasCode(generatePreflightErr, vaultservice.CodeForbidden) {
				writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeEncrypt, protectedResourceMetadataURL(h.authConfig))
			} else if errors.Is(generatePreflightErr, context.Canceled) || errors.Is(generatePreflightErr, context.DeadlineExceeded) {
				writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
			} else {
				writeServiceError(w, generatePreflightErr)
			}
			return
		}
	} else if actor.Kind() == caller.KindBearer {
		if verifyCall {
			verifyPreflightErr = h.service.PreflightAttestationVerify(r.Context(), actor)
		} else if (headerMethod == "server/discover" || headerMethod == "tools/list") && actor.HasScope(vaultservice.ScopeAttestationVerify) {
			// A verify-only bearer may discover the verification tool without
			// profile-read or profile Casbin access.
		} else if mcpHeaderRequiredScope(headerMethod, headerToolName) == vaultservice.ScopeProfileRead {
			verifyPreflightErr = h.preflightProfiles(r.Context(), actor)
		} else if headerMethod == "tools/call" {
			verifyPreflightErr = h.preflightOperation(r.Context(), actor, vaultservice.Operation(headerToolName))
		}
		if verifyPreflightErr != nil && !(verifyCall &&
			(vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeFeatureUnavailable) ||
				vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeAttestationUnavailable))) {
			scope := mcpHeaderRequiredScope(headerMethod, headerToolName)
			if vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeForbidden) {
				writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope, protectedResourceMetadataURL(h.authConfig))
			} else if errors.Is(verifyPreflightErr, context.Canceled) || errors.Is(verifyPreflightErr, context.DeadlineExceeded) {
				writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
			} else {
				writeServiceError(w, verifyPreflightErr)
			}
			return
		}
	}

	var lease *vaultservice.Lease
	var err error
	var leaseContext context.Context
	if verifyCall {
		if verifyPreflightErr == nil && actor.Kind() != caller.KindBearer {
			verifyPreflightErr = h.service.PreflightAttestationVerify(r.Context(), actor)
		}
		if verifyPreflightErr != nil && !vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeFeatureUnavailable) && !vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeAttestationUnavailable) {
			if vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeForbidden) && actor.Kind() == caller.KindBearer {
				writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeAttestationVerify, protectedResourceMetadataURL(h.authConfig))
			} else {
				writeServiceError(w, verifyPreflightErr)
			}
			return
		}
		if verifyPreflightErr == nil {
			lease, err = h.service.VerifierAdmission().TryAcquire(r.Context())
			if err != nil {
				if errors.Is(err, vaultservice.ErrVerifierAdmissionSaturated) || errors.Is(err, vaultservice.ErrAdmissionSaturated) {
					w.Header().Set("Retry-After", "1")
					writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeAttestationBusy), "rotation attestation verification is busy")
				} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
				} else {
					writeServiceError(w, err)
				}
				return
			}
			defer lease.Release()
			leaseContext = lease.Context(r.Context())
		} else {
			leaseContext = r.Context()
		}
	} else {
		lease, err = h.service.Admission().TryAcquire(r.Context())
		if err != nil {
			if errors.Is(err, vaultservice.ErrAdmissionSaturated) {
				if generateCall {
					writeGenerateAdmissionSaturated(w, h.service.Admission())
				} else {
					writeAdmissionSaturated(w, h.service.Admission())
				}
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
			} else {
				writeServiceError(w, err)
			}
			return
		}
		defer lease.Release()
		leaseContext = lease.Context(r.Context())
	}

	readBody := readMCPBody
	if verifyCall {
		readBody = func(w http.ResponseWriter, r *http.Request) ([]byte, error) {
			return readMCPBodyLimit(w, r, maxMCPVerifyBodyBytes)
		}
	}
	raw, err := readBody(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			mcpWriteHTTPError(w, http.StatusRequestEntityTooLarge, nil, mcpErrorInvalidRequest, "request is too large", nil)
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorParse, "parse error", nil)
		}
		return
	}
	request, err := decodeMCPRequest(raw)
	if err != nil {
		code := mcpErrorInvalidRequest
		message := "invalid request"
		if !json.Valid(raw) {
			code = mcpErrorParse
			message = "parse error"
		}
		mcpWriteHTTPError(w, http.StatusBadRequest, nil, code, message, nil)
		return
	}
	if request.sdk.Method != headerMethod {
		mcpWriteHTTPError(w, http.StatusBadRequest, &request.id, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return
	}
	if err := validateMCPNameMirror(request.sdk.Method, request.sdk.Params, headerToolName); err != nil {
		mcpWriteMCPValidationError(w, request.id, err)
		return
	}
	switch request.sdk.Method {
	case "server/discover":
		if err := validateMCPMeta(request.sdk.Params, headerVersion); err != nil {
			mcpWriteMCPValidationError(w, request.id, err)
			return
		}
		h.serveMCPDiscover(w, request.id, request.sdk.Params)
	case "tools/list":
		if err := validateMCPMeta(request.sdk.Params, headerVersion); err != nil {
			mcpWriteMCPValidationError(w, request.id, err)
			return
		}
		h.serveMCPListTools(w, request.id, request.sdk.Params, actor)
	case "tools/call":
		if err := validateMCPMeta(request.sdk.Params, headerVersion); err != nil {
			mcpWriteMCPValidationError(w, request.id, err)
			return
		}
		h.serveMCPToolCall(w, r, request.id, request.sdk.Params, headerToolName, actor, lease, leaseContext, verifyPreflightErr)
	default:
		mcpWriteHTTPError(w, http.StatusNotFound, &request.id, mcpErrorMethodNotFound, "method not found", nil)
	}
}

func (h *Handler) serveMCPDiscover(w http.ResponseWriter, id json.RawMessage, params json.RawMessage) {
	if _, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}}); err != nil {
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
		return
	}
	mcpWriteResult(w, id, mcpDiscoverResult{
		Meta:              mcpResultMeta(),
		ResultType:        "complete",
		TTLMs:             0,
		CacheScope:        "private",
		SupportedVersions: []string{mcpProtocolVersion},
		Capabilities:      &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
	})
}

func (h *Handler) serveMCPListTools(w http.ResponseWriter, id json.RawMessage, params json.RawMessage, actor caller.Caller) {
	fields, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}, "cursor": {}})
	if err != nil {
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
		return
	}
	if raw, ok := fields["cursor"]; ok {
		cursor, err := decodeOperationString(raw)
		if err != nil || cursor != "" {
			mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
			return
		}
	}
	mcpWriteResult(w, id, mcpListToolsResult{
		Meta:       mcpResultMeta(),
		ResultType: "complete",
		TTLMs:      0,
		CacheScope: "private",
		Tools:      h.mcpTools(actor),
	})
}

func (h *Handler) serveMCPToolCall(w http.ResponseWriter, r *http.Request, id json.RawMessage, params json.RawMessage, headerToolName string, actor caller.Caller, lease *vaultservice.Lease, leaseContext context.Context, verifyPreflightErr error) {
	verifyOutcome := "failed"
	verifyCall := headerToolName == "verify_rotation_attestation"
	if verifyCall {
		defer func() {
			if h.metrics != nil {
				h.metrics.observeAttestationVerify(verifyOutcome)
			}
		}()
	}
	call, arguments, err := decodeMCPCallParams(params)
	if err != nil {
		if verifyCall {
			verifyOutcome = "invalid"
		}
		if errors.Is(err, errMCPToolArguments) {
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
		return
	}
	if call.Name != headerToolName {
		if verifyCall {
			verifyOutcome = "invalid"
		}
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return
	}
	attestationRequested := call.Name == "rotate" && strings.TrimSpace(arguments["attestation"]) != ""
	attestationOutcome := "failed"
	if attestationRequested {
		defer func() {
			if h.metrics != nil {
				h.metrics.observeAttestationIssued(attestationOutcome)
			}
		}()
	}
	switch call.Name {
	case "list_profiles":
		if len(arguments) != 0 {
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		profiles, err := h.service.ListProfiles(r.Context(), actor)
		if err != nil {
			if mcpServiceUnavailable(err) {
				mcpWriteServiceUnavailable(w, err)
				return
			}
			if vaultservice.HasCode(err, vaultservice.CodeForbidden) {
				mcpWriteResult(w, id, mcpCallResult(profilesResponse{Profiles: []apimodels.Profile{}}, false))
				return
			}
			mcpWriteToolError(w, id, mcpTextToolFailure)
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
		mcpWriteResult(w, id, mcpCallResult(profilesResponse{Profiles: public}, false))
	case "verify_rotation_attestation":
		if lease == nil {
			code := vaultservice.CodeAttestationUnavailable
			verifyOutcome = "unavailable"
			if vaultservice.HasCode(verifyPreflightErr, vaultservice.CodeFeatureUnavailable) {
				code = vaultservice.CodeFeatureUnavailable
				verifyOutcome = "feature_unavailable"
			}
			mcpWriteStructuredToolError(w, id, code, "")
			return
		}
		verifyRaw := map[string]json.RawMessage{
			"attestation":     json.RawMessage(arguments["attestation"]),
			"inputVaultText":  json.RawMessage(strconv.Quote(arguments["inputVaultText"])),
			"outputVaultText": json.RawMessage(strconv.Quote(arguments["outputVaultText"])),
		}
		if expected := strings.TrimSpace(arguments["expectedBinding"]); expected != "" {
			verifyRaw["expectedBinding"] = json.RawMessage(expected)
		}
		verifyRequestBytes, marshalErr := json.Marshal(verifyRaw)
		if marshalErr != nil {
			verifyOutcome = "invalid"
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		request, parseErr := parseVerifyAttestationRequest(verifyRequestBytes)
		if parseErr != nil {
			verifyOutcome = "invalid"
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		claims, verifyErr := h.service.VerifyAttestation(leaseContext, request.Attestation, request.InputVaultText, request.OutputVaultText, request.ExpectedBinding)
		if reason, ok := attestation.VerificationReasonOf(verifyErr); ok {
			verifyOutcome = "invalid"
			response := verifyAttestationResponse{Valid: false, Reason: reason}
			if claims.Issuer != "" && reason != attestation.SignatureInvalid && reason != attestation.UnknownKey && reason != attestation.IssuerMismatch {
				response.Attestation = h.safeClaimsResponse(request.Attestation, claims)
			}
			mcpWriteResult(w, id, mcpCallResult(response, false))
			return
		}
		if verifyErr != nil {
			if vaultservice.HasCode(verifyErr, vaultservice.CodeInvalidRequest) || errors.Is(verifyErr, attestation.ErrMalformed) {
				verifyOutcome = "invalid"
				mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			} else if code, ok := mcpAttestationErrorCode(verifyErr); ok {
				verifyOutcome = attestationOutcomeFromError(verifyErr)
				mcpWriteStructuredToolError(w, id, code, "")
			} else {
				verifyOutcome = "unavailable"
				mcpWriteStructuredToolError(w, id, vaultservice.CodeTemporarilyUnavailable, "service is temporarily unavailable")
			}
			return
		}
		verifyOutcome = "success"
		mcpWriteResult(w, id, mcpCallResult(verifyAttestationResponse{Valid: true, Attestation: h.safeClaimsResponse(request.Attestation, claims)}, false))
	case "generate_password", "generate_token", "generate_ssh_keypair", "generate_age_identity", "generate_x509_csr":
		h.serveMCPGenerateTool(w, id, actor, leaseContext, call.Name, call.Arguments)
	case "encrypt", "decrypt", "rotate":
		command, response, ok := mcpCommand(call.Name, arguments)
		if !ok {
			if attestationRequested {
				attestationOutcome = "invalid"
			}
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		prepared, err := h.service.Prepare(leaseContext, actor, command, lease)
		if err != nil {
			if attestationRequested {
				attestationOutcome = attestationOutcomeFromError(err)
			}
			if code, ok := mcpAttestationErrorCode(err); ok {
				mcpWriteStructuredToolError(w, id, code, "")
				return
			}
			if mcpServiceUnavailable(err) {
				mcpWriteServiceUnavailable(w, err)
				return
			}
			if actor.Kind() != caller.KindAnonymous && vaultservice.IsPolicyDenied(err) {
				writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
				return
			}
			mcpWriteToolError(w, id, mcpTextToolFailure)
			return
		}
		if call.Name == "rotate" {
			result, runErr := prepared.RunResult(leaseContext)
			if runErr != nil {
				if attestationRequested {
					attestationOutcome = attestationOutcomeFromError(runErr)
				}
				if code, ok := mcpAttestationErrorCode(runErr); ok {
					mcpWriteStructuredToolError(w, id, code, "")
					return
				}
				if mcpServiceUnavailable(runErr) {
					mcpWriteServiceUnavailable(w, runErr)
					return
				}
				mcpWriteToolError(w, id, mcpTextToolFailure)
				return
			}
			if attestationRequested {
				if result.Attestation != nil {
					attestationOutcome = "success"
				} else {
					attestationOutcome = "failed"
				}
			}
			mcpWriteResult(w, id, mcpCallResult(rotationResponseWithAttestation{VaultText: result.VaultText, Attestation: result.Attestation}, false))
			return
		}
		output, runErr := prepared.Run(leaseContext)
		if runErr != nil {
			if mcpServiceUnavailable(runErr) {
				mcpWriteServiceUnavailable(w, runErr)
				return
			}
			mcpWriteToolError(w, id, mcpTextToolFailure)
			return
		}
		mcpWriteResult(w, id, mcpCallResult(response(output), false))
	default:
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
	}
}

type mcpRequest struct {
	id  json.RawMessage
	sdk *jsonrpc.Request
}

func decodeMCPRequest(raw []byte) (mcpRequest, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{"jsonrpc": {}, "id": {}, "method": {}, "params": {}})
	if err != nil {
		return mcpRequest{}, err
	}
	versionRaw, ok := fields["jsonrpc"]
	if !ok {
		return mcpRequest{}, errors.New("missing jsonrpc")
	}
	versionValue, err := decodeOperationString(versionRaw)
	if err != nil || versionValue != "2.0" {
		return mcpRequest{}, errors.New("invalid jsonrpc")
	}
	id, ok := fields["id"]
	if !ok || len(bytes.TrimSpace(id)) == 0 || !validJSONRPCID(id) {
		return mcpRequest{}, errors.New("missing id")
	}
	methodRaw, ok := fields["method"]
	if !ok {
		return mcpRequest{}, errors.New("missing method")
	}
	method, err := decodeOperationString(methodRaw)
	if err != nil {
		return mcpRequest{}, err
	}
	params, ok := fields["params"]
	if !ok {
		return mcpRequest{}, errors.New("missing params")
	}
	if !jsonObject(params) {
		return mcpRequest{}, errors.New("params must be an object")
	}
	sdkID, err := sdkJSONRPCID(id)
	if err != nil {
		return mcpRequest{}, err
	}
	return mcpRequest{id: id, sdk: &jsonrpc.Request{ID: sdkID, Method: method, Params: params}}, nil
}

func validJSONRPCID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false
	}
	if trimmed[0] == '"' {
		var value string
		return json.Unmarshal(trimmed, &value) == nil
	}
	if bytes.ContainsAny(trimmed, ".eE") {
		return false
	}
	_, err := strconv.ParseInt(string(trimmed), 10, 64)
	return err == nil
}

func sdkJSONRPCID(raw json.RawMessage) (jsonrpc.ID, error) {
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return jsonrpc.ID{}, err
		}
		return jsonrpc.MakeID(value)
	}
	value, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return jsonrpc.ID{}, err
	}
	return jsonrpc.MakeID(float64(value))
}

type mcpValidationError struct {
	code    int
	message string
}

func (e *mcpValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func mcpInvalidParamsError(message string) error {
	return &mcpValidationError{code: mcpErrorInvalidParams, message: message}
}

func mcpHeaderMismatchError(message string) error {
	return &mcpValidationError{code: mcpErrorHeaderMismatch, message: message}
}

func mcpWriteMCPValidationError(w http.ResponseWriter, id json.RawMessage, err error) {
	code := mcpErrorInvalidParams
	message := "invalid params"
	var validationErr *mcpValidationError
	if errors.As(err, &validationErr) {
		code = validationErr.code
		if validationErr.message != "" {
			message = validationErr.message
		}
	}
	mcpWriteHTTPError(w, http.StatusBadRequest, &id, code, message, nil)
}

func validateMCPNameMirror(method string, params json.RawMessage, headerName string) error {
	field := ""
	switch method {
	case "tools/call", "prompts/get":
		field = "name"
	case "resources/read":
		field = "uri"
	default:
		return nil
	}
	fields, err := decodeOpenJSONObject(params)
	if err != nil {
		return nil
	}
	rawName, ok := fields[field]
	if !ok {
		return nil
	}
	bodyName, err := decodeOperationString(rawName)
	if err != nil || bodyName == headerName {
		return nil
	}
	return mcpHeaderMismatchError("HeaderMismatch")
}

func validateMCPMeta(params json.RawMessage, headerVersion string) error {
	fields, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}, "name": {}, "arguments": {}, "cursor": {}})
	if err != nil {
		return mcpInvalidParamsError("invalid params")
	}
	rawMeta, ok := fields["_meta"]
	if !ok {
		return mcpInvalidParamsError("invalid params")
	}
	metaFields, err := decodeMCPMetaObject(rawMeta, map[string]struct{}{
		mcp.MetaKeyProtocolVersion:    {},
		mcp.MetaKeyClientCapabilities: {},
		mcp.MetaKeyClientInfo:         {},
	})
	if err != nil {
		return mcpInvalidParamsError("invalid params")
	}
	rawVersion, ok := metaFields[mcp.MetaKeyProtocolVersion]
	if !ok {
		return mcpInvalidParamsError("invalid params")
	}
	versionValue, err := decodeOperationString(rawVersion)
	if err != nil {
		return mcpInvalidParamsError("invalid params")
	}
	if versionValue != headerVersion {
		return mcpHeaderMismatchError("HeaderMismatch")
	}
	rawCapabilities, ok := metaFields[mcp.MetaKeyClientCapabilities]
	if !ok || validateMCPClientCapabilities(rawCapabilities) != nil {
		return mcpInvalidParamsError("invalid params")
	}
	if rawClientInfo, present := metaFields[mcp.MetaKeyClientInfo]; present {
		var implementation mcp.Implementation
		if err := decodeStrictJSON(rawClientInfo, &implementation); err != nil || implementation.Name == "" || implementation.Version == "" {
			return mcpInvalidParamsError("invalid params")
		}
	}
	return nil
}

func validateMCPClientCapabilities(raw json.RawMessage) error {
	if !jsonObject(raw) {
		return errors.New("client capabilities must be an object")
	}
	fields, err := decodeOpenJSONObject(raw)
	if err != nil {
		return err
	}
	known := map[string]struct{}{
		"experimental": {},
		"extensions":   {},
		"roots":        {},
		"sampling":     {},
		"elicitation":  {},
	}
	for name, value := range fields {
		if _, isKnown := known[name]; isKnown && !jsonObject(value) {
			return errors.New("client capability must be an object")
		}
	}
	var capabilities mcp.ClientCapabilities
	return json.Unmarshal(raw, &capabilities)
}

func decodeOpenJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("object required")
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("object key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("duplicate object key")
		}
		seen[key] = struct{}{}
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
		return nil, errors.New("object is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}

func decodeStrictJSON(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

var (
	mcpMetaNamePattern   = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)?$`)
	mcpMetaPrefixPattern = regexp.MustCompile(`^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$`)
)

func decodeMCPMetaObject(raw []byte, required map[string]struct{}) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("metadata must be a JSON object")
	}
	fields := make(map[string]json.RawMessage, len(required))
	seen := make(map[string]struct{}, len(required))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || !validMCPMetaKey(key) {
			return nil, errors.New("metadata key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("duplicate metadata key")
		}
		seen[key] = struct{}{}
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
		return nil, errors.New("metadata object is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}

func validMCPMetaKey(key string) bool {
	prefix, name, hasPrefix := strings.Cut(key, "/")
	if !hasPrefix {
		return mcpMetaNamePattern.MatchString(key)
	}
	return mcpMetaPrefixPattern.MatchString(prefix) && mcpMetaNamePattern.MatchString(name)
}

var errMCPToolArguments = errors.New("tool arguments are invalid")

func decodeMCPCallParams(params json.RawMessage) (mcp.CallToolParamsRaw, map[string]string, error) {
	fields, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}, "name": {}, "arguments": {}})
	if err != nil {
		return mcp.CallToolParamsRaw{}, nil, err
	}
	nameRaw, ok := fields["name"]
	if !ok {
		return mcp.CallToolParamsRaw{}, nil, errors.New("missing name")
	}
	name, err := decodeOperationString(nameRaw)
	if err != nil || name == "" {
		return mcp.CallToolParamsRaw{}, nil, errors.New("invalid name")
	}
	argsRaw, ok := fields["arguments"]
	if !ok {
		argsRaw = json.RawMessage(`{}`)
	}
	if !jsonObject(argsRaw) {
		return mcp.CallToolParamsRaw{}, nil, errors.New("invalid arguments")
	}
	arguments := map[string]string{}
	switch name {
	case "list_profiles":
		argFields, err := decodeStrictObject(argsRaw, map[string]struct{}{})
		if err != nil || len(argFields) != 0 {
			return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, nil, errMCPToolArguments
		}
	case "encrypt":
		arguments, err = decodeMCPStringArguments(argsRaw, map[string]struct{}{"profileId": {}, "plaintext": {}})
	case "decrypt":
		arguments, err = decodeMCPStringArguments(argsRaw, map[string]struct{}{"profileId": {}, "vaultText": {}})
	case "rotate":
		arguments, err = decodeMCPMixedArguments(argsRaw, map[string]struct{}{"sourceProfileId": {}, "destinationProfileId": {}, "vaultText": {}}, map[string]struct{}{"attestation": {}})
	case "verify_rotation_attestation":
		arguments, err = decodeMCPMixedArguments(argsRaw, map[string]struct{}{"attestation": {}, "inputVaultText": {}, "outputVaultText": {}}, map[string]struct{}{"attestation": {}, "expectedBinding": {}})
	case "generate_password", "generate_token", "generate_ssh_keypair", "generate_age_identity", "generate_x509_csr":
		// Generate owns a typed flat decoder so booleans, integers, nested X.509
		// objects, and omitted defaults are not coerced through string arguments.
	default:
		return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, nil, errors.New("unknown tool")
	}
	if err != nil {
		return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, nil, errMCPToolArguments
	}
	return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, arguments, nil
}

func decodeMCPMixedArguments(raw json.RawMessage, required, objectFields map[string]struct{}) (map[string]string, error) {
	allowed := make(map[string]struct{}, len(required)+len(objectFields))
	for key := range required {
		allowed[key] = struct{}{}
	}
	for key := range objectFields {
		allowed[key] = struct{}{}
	}
	fields, err := decodeStrictObject(raw, allowed)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(fields))
	for key, value := range fields {
		if _, isObject := objectFields[key]; isObject {
			if !jsonObject(value) {
				return nil, errors.New("object argument is invalid")
			}
			values[key] = string(value)
			continue
		}
		decoded, err := decodeOperationString(value)
		if err != nil {
			return nil, err
		}
		values[key] = decoded
	}
	for key := range required {
		if _, ok := values[key]; !ok {
			return nil, errors.New("missing required argument")
		}
	}
	return values, nil
}

func decodeMCPStringArguments(raw json.RawMessage, allowed map[string]struct{}) (map[string]string, error) {
	fields, err := decodeStrictObject(raw, allowed)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(fields))
	for key, value := range fields {
		decoded, err := decodeOperationString(value)
		if err != nil {
			return nil, err
		}
		values[key] = decoded
	}
	if len(values) != len(allowed) {
		return nil, errors.New("missing required argument")
	}
	return values, nil
}

func mcpCommand(name string, arguments map[string]string) (vaultservice.Command, func(string) any, bool) {
	switch name {
	case "encrypt":
		profileID, profileOK := arguments["profileId"]
		plaintext, plaintextOK := arguments["plaintext"]
		return vaultservice.Command{Operation: vaultservice.OperationEncrypt, ProfileID: profileID, Value: plaintext}, func(output string) any { return encryptResponse{VaultText: output} }, profileOK && plaintextOK
	case "decrypt":
		profileID, profileOK := arguments["profileId"]
		vaultText, vaultOK := arguments["vaultText"]
		return vaultservice.Command{Operation: vaultservice.OperationDecrypt, ProfileID: profileID, Value: vaultText}, func(output string) any { return decryptResponse{Plaintext: output} }, profileOK && vaultOK
	case "rotate":
		source, sourceOK := arguments["sourceProfileId"]
		destination, destinationOK := arguments["destinationProfileId"]
		vaultText, vaultOK := arguments["vaultText"]
		command := vaultservice.Command{Operation: vaultservice.OperationRotate, SourceProfileID: source, DestinationProfileID: destination, Value: vaultText}
		if raw, attestationOK := arguments["attestation"]; attestationOK {
			request, err := parseRotationAttestationRequest(json.RawMessage(raw))
			if err != nil {
				return vaultservice.Command{}, nil, false
			}
			command.Attestation = &vaultservice.AttestationRequest{Binding: request.Binding}
		}
		return command, func(output string) any { return rotateResponse{VaultText: output} }, sourceOK && destinationOK && vaultOK
	default:
		return vaultservice.Command{}, nil, false
	}
}

func mcpCallResult(structured any, isError bool) mcpCallToolResult {
	text, _ := json.Marshal(structured)
	result := mcpCallToolResult{
		Meta:       mcpResultMeta(),
		ResultType: "complete",
		TTLMs:      0,
		CacheScope: "private",
		IsError:    isError,
		Content:    []mcp.Content{&mcp.TextContent{Text: string(text)}},
	}
	if !isError {
		result.StructuredContent = structured
	}
	return result
}

func mcpWriteToolError(w http.ResponseWriter, id json.RawMessage, message string) {
	mcpWriteResult(w, id, mcpCallToolResult{
		Meta:       mcpResultMeta(),
		ResultType: "complete",
		TTLMs:      0,
		CacheScope: "private",
		IsError:    true,
		Content:    []mcp.Content{&mcp.TextContent{Text: message}},
	})
}

func mcpAttestationErrorCode(err error) (vaultservice.Code, bool) {
	for _, code := range []vaultservice.Code{
		vaultservice.CodeFeatureUnavailable,
		vaultservice.CodeAttestationUnavailable,
		vaultservice.CodeAttestationBusy,
	} {
		if vaultservice.HasCode(err, code) {
			return code, true
		}
	}
	return "", false
}

func mcpWriteStructuredToolError(w http.ResponseWriter, id json.RawMessage, code vaultservice.Code, message string) {
	if message == "" {
		switch code {
		case vaultservice.CodeFeatureUnavailable:
			message = "rotation attestations are disabled"
		case vaultservice.CodeAttestationUnavailable:
			message = "rotation attestation service is unavailable"
		case vaultservice.CodeAttestationBusy:
			message = "rotation attestation verification is busy"
		default:
			message = "service is temporarily unavailable"
		}
	}
	structured := map[string]any{"error": map[string]string{"code": string(code), "message": message}}
	result := mcpCallResult(structured, true)
	result.StructuredContent = structured
	mcpWriteResult(w, id, result)
}

func mcpServiceUnavailable(err error) bool {
	return vaultservice.HasCode(err, vaultservice.CodeNotReady) ||
		vaultservice.HasCode(err, vaultservice.CodeTemporarilyUnavailable) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func mcpWriteServiceUnavailable(w http.ResponseWriter, err error) {
	if vaultservice.HasCode(err, vaultservice.CodeNotReady) || vaultservice.HasCode(err, vaultservice.CodeTemporarilyUnavailable) {
		writeServiceError(w, err)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
}

func (h *Handler) mcpTools(actor caller.Caller) []*mcp.Tool {
	tools := make([]*mcp.Tool, 0, 10)
	bindingSchema := mcpObjectSchema(nil, map[string]any{
		"repository": mcpStringSchema(), "revision": mcpStringSchema(), "path": mcpStringSchema(), "selector": mcpStringSchema(),
	})
	encryptScope, _ := vaultservice.RequiredScope(vaultservice.OperationEncrypt)
	decryptScope, _ := vaultservice.RequiredScope(vaultservice.OperationDecrypt)
	rotateScope, _ := vaultservice.RequiredScope(vaultservice.OperationRotate)
	if mcpToolVisible(actor, vaultservice.ScopeProfileRead) {
		tools = append(tools, &mcp.Tool{
			Name: "list_profiles", Description: "List visible Vault profiles.",
			InputSchema:  mcpObjectSchema(nil, nil),
			OutputSchema: mcpObjectSchema([]string{"profiles"}, map[string]any{"profiles": map[string]any{"type": "array"}}),
		})
	}
	if mcpToolVisible(actor, encryptScope) {
		tools = append(tools, &mcp.Tool{
			Name: "encrypt", Description: "Encrypt UTF-8 plaintext with a Vaultsmith profile.",
			InputSchema:  mcpObjectSchema([]string{"profileId", "plaintext"}, map[string]any{"profileId": mcpStringSchema(), "plaintext": mcpStringSchema()}),
			OutputSchema: mcpObjectSchema([]string{"vaultText"}, map[string]any{"vaultText": mcpStringSchema()}),
		})
	}
	if mcpToolVisible(actor, decryptScope) {
		tools = append(tools, &mcp.Tool{
			Name: "decrypt", Description: "Decrypt Ansible Vault text with a Vaultsmith profile.",
			InputSchema:  mcpObjectSchema([]string{"profileId", "vaultText"}, map[string]any{"profileId": mcpStringSchema(), "vaultText": mcpStringSchema()}),
			OutputSchema: mcpObjectSchema([]string{"plaintext"}, map[string]any{"plaintext": mcpStringSchema()}),
		})
	}
	if mcpToolVisible(actor, rotateScope) {
		tools = append(tools, &mcp.Tool{
			Name:        "rotate",
			Description: "Rotate Vault text from one profile to another. An optional attestation authenticates the rotation statement; it is not an independent plaintext-equality proof.",
			InputSchema: mcpObjectSchema([]string{"sourceProfileId", "destinationProfileId", "vaultText"}, map[string]any{
				"sourceProfileId": mcpStringSchema(), "destinationProfileId": mcpStringSchema(), "vaultText": mcpStringSchema(),
				"attestation": mcpObjectSchema(nil, map[string]any{"binding": bindingSchema}),
			}),
			OutputSchema: mcpObjectSchema([]string{"vaultText"}, map[string]any{"vaultText": mcpStringSchema(), "attestation": mcpObjectSchema([]string{"protected", "payload", "signature"}, map[string]any{"protected": mcpStringSchema(), "payload": mcpStringSchema(), "signature": mcpStringSchema()})}),
		})
	}
	if h.service != nil && h.service.AttestationEnabled() && mcpToolVisible(actor, vaultservice.ScopeAttestationVerify) {
		tools = append(tools, &mcp.Tool{
			Name:        "verify_rotation_attestation",
			Description: "Verify a rotation attestation against supplied Vault envelopes. valid:true authenticates the attested rotation statement, not plaintext equality.",
			InputSchema: mcpObjectSchema([]string{"attestation", "inputVaultText", "outputVaultText"}, map[string]any{
				"attestation":    mcpObjectSchema([]string{"protected", "payload", "signature"}, map[string]any{"protected": mcpStringSchema(), "payload": mcpStringSchema(), "signature": mcpStringSchema()}),
				"inputVaultText": mcpStringSchema(), "outputVaultText": mcpStringSchema(), "expectedBinding": bindingSchema,
			}),
			OutputSchema: mcpObjectSchema([]string{"valid"}, map[string]any{
				"valid":  map[string]any{"type": "boolean"},
				"reason": mcpStringSchema(),
				"attestation": mcpObjectSchema([]string{"issuer", "issuedAt", "operation", "sourceProfileId", "destinationProfileId", "kid"}, map[string]any{
					"issuer":               mcpStringSchema(),
					"issuedAt":             mcpStringSchema(),
					"operation":            mcpStringSchema(),
					"sourceProfileId":      mcpStringSchema(),
					"destinationProfileId": mcpStringSchema(),
					"kid":                  mcpStringSchema(),
					"binding":              bindingSchema,
				}),
			}),
		})
	}
	if mcpToolVisible(actor, encryptScope) {
		tools = append(tools, mcpGenerateTools()...)
	}
	return tools
}

func mcpToolVisible(actor caller.Caller, scope string) bool {
	return actor.Kind() != caller.KindBearer || actor.HasScope(scope)
}

func mcpObjectSchema(required []string, properties map[string]any) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
	}
}

func mcpStringSchema() map[string]any {
	return map[string]any{"type": "string"}
}

func mcpResultMeta() mcp.Meta {
	return mcp.Meta{mcp.MetaKeyServerInfo: &mcp.Implementation{Name: "vaultsmith", Version: version.Version}}
}

func mcpHeaderRequiredScope(method, toolName string) string {
	switch method {
	case "server/discover", "tools/list":
		return vaultservice.ScopeProfileRead
	case "tools/call":
		switch toolName {
		case "list_profiles":
			return vaultservice.ScopeProfileRead
		case "encrypt":
			scope, _ := vaultservice.RequiredScope(vaultservice.OperationEncrypt)
			return scope
		case "generate_password", "generate_token", "generate_ssh_keypair", "generate_age_identity", "generate_x509_csr":
			return vaultservice.ScopeEncrypt
		case "decrypt":
			scope, _ := vaultservice.RequiredScope(vaultservice.OperationDecrypt)
			return scope
		case "rotate":
			scope, _ := vaultservice.RequiredScope(vaultservice.OperationRotate)
			return scope
		case "verify_rotation_attestation":
			return vaultservice.ScopeAttestationVerify
		default:
			return ""
		}
	default:
		return ""
	}
}

type mcpHeaders struct {
	protocolVersion string
	method          string
	toolName        string
}

type mcpHeadersContextKey struct{}

func parseMCPRequestHeaders(w http.ResponseWriter, r *http.Request) (mcpHeaders, bool) {
	version, ok := singletonHeader(r.Header, "MCP-Protocol-Version")
	if !ok {
		mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return mcpHeaders{}, false
	}
	if version != mcpProtocolVersion {
		mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorUnsupportedProtocol, "UnsupportedProtocolVersionError", mcp.UnsupportedProtocolVersionData{
			Supported: []string{mcpProtocolVersion},
			Requested: version,
		})
		return mcpHeaders{}, false
	}
	method, ok := singletonHeader(r.Header, "Mcp-Method")
	if !ok {
		mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return mcpHeaders{}, false
	}
	toolName := ""
	if method == "tools/call" || method == "resources/read" || method == "prompts/get" {
		encodedName, nameOK := singletonHeader(r.Header, "Mcp-Name")
		if !nameOK {
			mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
			return mcpHeaders{}, false
		}
		decodedName, err := decodeMCPNameHeader(encodedName)
		if err != nil {
			mcpWriteHTTPError(w, http.StatusBadRequest, nil, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
			return mcpHeaders{}, false
		}
		toolName = decodedName
	}
	return mcpHeaders{protocolVersion: version, method: method, toolName: toolName}, true
}

func requestWithMCPHeaders(r *http.Request, headers mcpHeaders) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), mcpHeadersContextKey{}, headers))
}

func mcpHeadersFromRequest(r *http.Request) (mcpHeaders, bool) {
	headers, ok := r.Context().Value(mcpHeadersContextKey{}).(mcpHeaders)
	return headers, ok
}

func singletonHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		return "", false
	}
	return value, true
}

func decodeMCPNameHeader(value string) (string, error) {
	if strings.HasPrefix(value, "=?base64?") {
		if !strings.HasSuffix(value, "?=") {
			return "", errors.New("invalid name header")
		}
		payload := strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?=")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil || !utf8.Valid(decoded) {
			return "", errors.New("invalid name header")
		}
		return string(decoded), nil
	}
	return value, nil
}

func mcpAccepts(values []string) bool {
	if len(values) == 0 {
		return false
	}
	acceptJSON := false
	acceptEventStream := false
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if !positiveHTTPMediaQuality(parameters) {
				continue
			}
			switch strings.ToLower(mediaType) {
			case mcpContentTypeApplicationJSON:
				acceptJSON = true
			case mcpContentTypeEventStream:
				acceptEventStream = true
			}
		}
	}
	return acceptJSON && acceptEventStream
}

func positiveHTTPMediaQuality(parameters map[string]string) bool {
	quality, present := parameters["q"]
	if !present {
		return true
	}
	if quality == "0" || quality == "0." {
		return false
	}
	if quality == "1" || quality == "1." {
		return true
	}
	if len(quality) < 3 || len(quality) > 5 || quality[1] != '.' {
		return false
	}
	digits := quality[2:]
	for index := range digits {
		if digits[index] < '0' || digits[index] > '9' {
			return false
		}
	}
	switch quality[0] {
	case '0':
		return strings.Trim(digits, "0") != ""
	case '1':
		return strings.Trim(digits, "0") == ""
	default:
		return false
	}
}

func readMCPBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return readMCPBodyLimit(w, r, MaxRequestBodyBytes)
}

func readMCPBodyLimit(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("body must be UTF-8")
	}
	return raw, nil
}

func jsonObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func mcpWriteResult(w http.ResponseWriter, id json.RawMessage, result any) {
	mcpWrite(w, http.StatusOK, mcpJSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func mcpWriteHTTPError(w http.ResponseWriter, status int, id *json.RawMessage, code int, message string, data any) {
	responseID := json.RawMessage("null")
	if id != nil {
		responseID = *id
	}
	mcpWrite(w, status, mcpJSONRPCResponse{
		JSONRPC: "2.0",
		ID:      responseID,
		Error:   &mcpJSONRPCError{Code: code, Message: message, Data: data},
	})
}

func mcpWrite(w http.ResponseWriter, status int, response mcpJSONRPCResponse) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	ensureRequestID(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}
