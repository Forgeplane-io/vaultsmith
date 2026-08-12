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
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/forgeplane-io/vaultsmith/backend/internal/version"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpProtocolVersion = "2026-07-28"

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
	if actor.Kind() == caller.KindBearer {
		var preflightErr error
		if mcpHeaderRequiredScope(headerMethod, headerToolName) == vaultservice.ScopeProfileRead {
			preflightErr = h.preflightProfiles(r.Context(), actor)
		} else if headerMethod == "tools/call" {
			preflightErr = h.preflightOperation(r.Context(), actor, vaultservice.Operation(headerToolName))
		}
		if preflightErr != nil {
			scope := mcpHeaderRequiredScope(headerMethod, headerToolName)
			if vaultservice.HasCode(preflightErr, vaultservice.CodeForbidden) {
				writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", scope)
			} else {
				writeServiceError(w, preflightErr)
			}
			return
		}
	}

	lease, err := h.service.Admission().TryAcquire(r.Context())
	if err != nil {
		if errors.Is(err, vaultservice.ErrAdmissionSaturated) {
			writeAdmissionSaturated(w, h.service.Admission())
		} else {
			writeServiceError(w, err)
		}
		return
	}
	defer lease.Release()
	leaseContext := lease.Context(r.Context())

	raw, err := readMCPBody(w, r)
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
	if err := validateMCPMeta(request.sdk.Params, headerVersion); err != nil {
		mcpWriteHTTPError(w, http.StatusBadRequest, &request.id, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return
	}

	switch request.sdk.Method {
	case "server/discover":
		h.serveMCPDiscover(w, request.id)
	case "tools/list":
		h.serveMCPListTools(w, request.id, request.sdk.Params)
	case "tools/call":
		h.serveMCPToolCall(w, r, request.id, request.sdk.Params, headerToolName, actor, lease, leaseContext)
	default:
		mcpWriteHTTPError(w, http.StatusNotFound, &request.id, mcpErrorMethodNotFound, "method not found", nil)
	}
}

func (h *Handler) serveMCPDiscover(w http.ResponseWriter, id json.RawMessage) {
	mcpWriteResult(w, id, mcpDiscoverResult{
		Meta:              mcpResultMeta(),
		ResultType:        "complete",
		TTLMs:             0,
		CacheScope:        "private",
		SupportedVersions: []string{mcpProtocolVersion},
		Capabilities:      &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
	})
}

func (h *Handler) serveMCPListTools(w http.ResponseWriter, id json.RawMessage, params json.RawMessage) {
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
		Tools:      mcpTools(),
	})
}

func (h *Handler) serveMCPToolCall(w http.ResponseWriter, r *http.Request, id json.RawMessage, params json.RawMessage, headerToolName string, actor caller.Caller, lease *vaultservice.Lease, leaseContext context.Context) {
	call, arguments, err := decodeMCPCallParams(params)
	if err != nil {
		if errors.Is(err, errMCPToolArguments) {
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorInvalidParams, "invalid params", nil)
		return
	}
	if call.Name != headerToolName {
		mcpWriteHTTPError(w, http.StatusBadRequest, &id, mcpErrorHeaderMismatch, "HeaderMismatch", nil)
		return
	}
	switch call.Name {
	case "list_profiles":
		if len(arguments) != 0 {
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		profiles, err := h.service.ListProfiles(r.Context(), actor)
		if err != nil {
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
	case "encrypt", "decrypt", "rotate":
		command, response, ok := mcpCommand(call.Name, arguments)
		if !ok {
			mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
			return
		}
		prepared, err := h.service.Prepare(leaseContext, actor, command, lease)
		if err != nil {
			if actor.Kind() != caller.KindAnonymous && vaultservice.IsPolicyDenied(err) {
				writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
				return
			}
			mcpWriteToolError(w, id, mcpTextToolFailure)
			return
		}
		output, err := prepared.Run(leaseContext)
		if err != nil {
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
	if _, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}, "name": {}, "arguments": {}, "cursor": {}}); err != nil {
		return mcpRequest{}, err
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

func validateMCPMeta(params json.RawMessage, headerVersion string) error {
	fields, err := decodeStrictObject(params, map[string]struct{}{"_meta": {}, "name": {}, "arguments": {}, "cursor": {}})
	if err != nil {
		return err
	}
	rawMeta, ok := fields["_meta"]
	if !ok {
		return errors.New("missing meta")
	}
	metaFields, err := decodeMCPMetaObject(rawMeta, map[string]struct{}{
		mcp.MetaKeyProtocolVersion:    {},
		mcp.MetaKeyClientCapabilities: {},
		mcp.MetaKeyClientInfo:         {},
	})
	if err != nil {
		return err
	}
	rawVersion, ok := metaFields[mcp.MetaKeyProtocolVersion]
	if !ok {
		return errors.New("missing meta version")
	}
	versionValue, err := decodeOperationString(rawVersion)
	if err != nil || versionValue != headerVersion {
		return errors.New("meta version mismatch")
	}
	rawCapabilities, ok := metaFields[mcp.MetaKeyClientCapabilities]
	if !ok || validateMCPClientCapabilities(rawCapabilities) != nil {
		return errors.New("missing client capabilities")
	}
	if rawClientInfo, present := metaFields[mcp.MetaKeyClientInfo]; present {
		var implementation mcp.Implementation
		if err := decodeStrictJSON(rawClientInfo, &implementation); err != nil || implementation.Name == "" || implementation.Version == "" {
			return errors.New("invalid client info")
		}
	}
	return nil
}

func validateMCPClientCapabilities(raw json.RawMessage) error {
	if !jsonObject(raw) {
		return errors.New("client capabilities must be an object")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{"experimental": {}, "extensions": {}, "roots": {}, "sampling": {}, "elicitation": {}})
	if err != nil {
		return err
	}
	for _, value := range fields {
		if !jsonObject(value) {
			return errors.New("client capability must be an object")
		}
	}
	var capabilities mcp.ClientCapabilities
	return json.Unmarshal(raw, &capabilities)
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
		arguments, err = decodeMCPStringArguments(argsRaw, map[string]struct{}{"sourceProfileId": {}, "destinationProfileId": {}, "vaultText": {}})
	default:
		return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, nil, errors.New("unknown tool")
	}
	if err != nil {
		return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, nil, errMCPToolArguments
	}
	return mcp.CallToolParamsRaw{Name: name, Arguments: argsRaw}, arguments, nil
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
		return vaultservice.Command{Operation: vaultservice.OperationRotate, SourceProfileID: source, DestinationProfileID: destination, Value: vaultText}, func(output string) any { return rotateResponse{VaultText: output} }, sourceOK && destinationOK && vaultOK
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

func mcpTools() []*mcp.Tool {
	return []*mcp.Tool{
		{Name: "list_profiles", Description: "List visible Vault profiles.", InputSchema: mcpObjectSchema(nil, nil), OutputSchema: mcpObjectSchema([]string{"profiles"}, map[string]any{"profiles": map[string]any{"type": "array"}})},
		{Name: "encrypt", Description: "Encrypt UTF-8 plaintext with a Vaultsmith profile.", InputSchema: mcpObjectSchema([]string{"profileId", "plaintext"}, map[string]any{"profileId": mcpStringSchema(), "plaintext": mcpStringSchema()}), OutputSchema: mcpObjectSchema([]string{"vaultText"}, map[string]any{"vaultText": mcpStringSchema()})},
		{Name: "decrypt", Description: "Decrypt Ansible Vault text with a Vaultsmith profile.", InputSchema: mcpObjectSchema([]string{"profileId", "vaultText"}, map[string]any{"profileId": mcpStringSchema(), "vaultText": mcpStringSchema()}), OutputSchema: mcpObjectSchema([]string{"plaintext"}, map[string]any{"plaintext": mcpStringSchema()})},
		{Name: "rotate", Description: "Rotate Vault text from one profile to another.", InputSchema: mcpObjectSchema([]string{"sourceProfileId", "destinationProfileId", "vaultText"}, map[string]any{"sourceProfileId": mcpStringSchema(), "destinationProfileId": mcpStringSchema(), "vaultText": mcpStringSchema()}), OutputSchema: mcpObjectSchema([]string{"vaultText"}, map[string]any{"vaultText": mcpStringSchema()})},
	}
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
		case "decrypt":
			scope, _ := vaultservice.RequiredScope(vaultservice.OperationDecrypt)
			return scope
		case "rotate":
			scope, _ := vaultservice.RequiredScope(vaultservice.OperationRotate)
			return scope
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
	if method == "tools/call" {
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
