package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/forgeplane-io/vaultsmith/backend/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

func mcpOffHandler() http.Handler {
	cfg := config.AuthConfig{Mode: config.AuthModeOff, CORS: config.CORSConfig{AllowedOrigins: []string{"https://client.example"}}}
	return WrapSecurityWithOptions(newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{value: "vault-output"}), cfg, SecurityOptions{MCPEnabled: true})
}

func newMCPRequest(method, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", method)
	return request
}

func TestMCPAcceptRequiresBothMediaTypesWithPositiveValidQuality(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "default quality", values: []string{"application/json, text/event-stream"}, want: true},
		{name: "positive quality", values: []string{"application/json;q=0.5, text/event-stream;q=1.000"}, want: true},
		{name: "JSON explicitly unacceptable", values: []string{"application/json;q=0, text/event-stream"}},
		{name: "event stream explicitly unacceptable", values: []string{"application/json, text/event-stream;q=0.000"}},
		{name: "invalid quality", values: []string{"application/json;q=bogus, text/event-stream"}},
		{name: "quality above one", values: []string{"application/json;q=1.1, text/event-stream"}},
		{name: "too many quality digits", values: []string{"application/json;q=0.1234, text/event-stream"}},
		{name: "missing event stream", values: []string{"application/json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mcpAccepts(test.values); got != test.want {
				t.Fatalf("mcpAccepts(%q) = %t, want %t", test.values, got, test.want)
			}
		})
	}
}

func TestMCPDisabledReturns404IncludingPreflight(t *testing.T) {
	cfg := config.AuthConfig{Mode: config.AuthModeOff, CORS: config.CORSConfig{AllowedOrigins: []string{"https://client.example"}}}
	handler := WrapSecurityWithOptions(newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}), cfg, SecurityOptions{})
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "https://vaultsmith.example.test/mcp", nil)
			request.Header.Set("Origin", "https://client.example")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("disabled MCP advertised CORS: %q", response.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestMCPEnabledCORSPreflight(t *testing.T) {
	handler := mcpOffHandler()
	request := httptest.NewRequest(http.MethodOptions, "https://vaultsmith.example.test/mcp", nil)
	request.Header.Set("Origin", "https://client.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Access-Control-Allow-Headers"), "MCP-Protocol-Version") {
		t.Fatalf("Access-Control-Allow-Headers = %q", response.Header().Get("Access-Control-Allow-Headers"))
	}
	if strings.Contains(response.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("off-mode preflight advertised Authorization: %q", response.Header().Get("Access-Control-Allow-Headers"))
	}
}

func TestMCPEnabledNonPreflightOptionsIsMethodNotAllowed(t *testing.T) {
	handler := mcpOffHandler()
	request := httptest.NewRequest(http.MethodOptions, "https://vaultsmith.example.test/mcp", nil)
	request.Header.Set("Origin", "https://client.example")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", response.Header().Get("Allow"))
	}
}

func TestMCPDiscoverAndListUseCompletePrivateResults(t *testing.T) {
	handler := mcpOffHandler()
	for _, test := range []struct {
		name   string
		method string
		body   string
	}{
		{name: "discover", method: "server/discover", body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + mcpMeta + `}}`},
		{name: "tools list", method: "tools/list", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + mcpMeta + `}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newMCPRequest(test.method, test.body))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			var envelope map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			result := envelope["result"].(map[string]any)
			if result["resultType"] != "complete" || result["ttlMs"].(float64) != 0 || result["cacheScope"] != "private" {
				t.Fatalf("result cache fields = %#v", result)
			}
			if test.method == "tools/list" {
				tools := result["tools"].([]any)
				names := []string{}
				for _, tool := range tools {
					names = append(names, tool.(map[string]any)["name"].(string))
				}
				if strings.Join(names, ",") != "list_profiles,encrypt,decrypt,rotate" {
					t.Fatalf("tool order = %#v", names)
				}
			}
		})
	}
}

func TestMCPUnsupportedJSONRPCMethodReturnsMethodNotFound(t *testing.T) {
	handler := mcpOffHandler()
	request := newMCPRequest("resources/list", `{"jsonrpc":"2.0","id":9,"method":"resources/list","params":{`+mcpMeta+`}}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error mcpJSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != mcpErrorMethodNotFound {
		t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorMethodNotFound)
	}
}

func TestMCPUnsupportedMethodsPreserveIDAndRequireMethodNameHeader(t *testing.T) {
	tests := []struct {
		method string
		params string
		name   string
	}{
		{method: "resources/read", params: `{"uri":"vaultsmith://profiles/dev",` + mcpMeta + `}`, name: "vaultsmith://profiles/dev"},
		{method: "prompts/get", params: `{"name":"synthetic-prompt","arguments":{},` + mcpMeta + `}`, name: "synthetic-prompt"},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			handler := mcpOffHandler()
			request := newMCPRequest(test.method, `{"jsonrpc":"2.0","id":"preserved","method":"`+test.method+`","params":`+test.params+`}`)
			request.Header.Set("Mcp-Name", test.name)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: %s", response.Code, response.Body.String())
			}
			var envelope struct {
				ID    json.RawMessage `json:"id"`
				Error mcpJSONRPCError `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if string(envelope.ID) != `"preserved"` {
				t.Fatalf("response id = %s, want preserved request id", envelope.ID)
			}
			if envelope.Error.Code != mcpErrorMethodNotFound {
				t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorMethodNotFound)
			}
		})
	}
}

func TestMCPUnsupportedMethodsRejectMismatchedMirroredName(t *testing.T) {
	tests := []struct {
		method string
		params string
		name   string
	}{
		{method: "resources/read", params: `{"uri":"vaultsmith://profiles/dev",` + mcpMeta + `}`, name: "other-resource"},
		{method: "prompts/get", params: `{"name":"synthetic-prompt","arguments":{},` + mcpMeta + `}`, name: "other-prompt"},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			handler := mcpOffHandler()
			request := newMCPRequest(test.method, `{"jsonrpc":"2.0","id":"preserved","method":"`+test.method+`","params":`+test.params+`}`)
			request.Header.Set("Mcp-Name", test.name)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
			var envelope struct {
				ID    json.RawMessage `json:"id"`
				Error mcpJSONRPCError `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if string(envelope.ID) != `"preserved"` || envelope.Error.Code != mcpErrorHeaderMismatch {
				t.Fatalf("response = %#v, want preserved id and HeaderMismatch", envelope)
			}
		})
	}
}

func TestMCPUnsupportedMethodNameHeadersAreRequired(t *testing.T) {
	for _, method := range []string{"resources/read", "prompts/get"} {
		t.Run(method, func(t *testing.T) {
			handler := mcpOffHandler()
			params := `{"uri":"vaultsmith://profiles/dev",` + mcpMeta + `}`
			if method == "prompts/get" {
				params = `{"name":"synthetic-prompt","arguments":{},` + mcpMeta + `}`
			}
			request := newMCPRequest(method, `{"jsonrpc":"2.0","id":10,"method":"`+method+`","params":`+params+`}`)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
			var envelope struct {
				Error mcpJSONRPCError `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != mcpErrorHeaderMismatch {
				t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorHeaderMismatch)
			}
		})
	}
}

func TestMCPMetaAcceptsCustomClientCapabilities(t *testing.T) {
	handler := mcpOffHandler()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"vendor/custom":{}}}}}`
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, newMCPRequest("server/discover", body))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestMCPNotReadyServiceFailureReturnsHTTP503(t *testing.T) {
	cfg := config.AuthConfig{Mode: config.AuthModeOff}
	api := NewWithDependencies(nil, nil, Dependencies{AuthConfig: cfg})
	handler := WrapSecurityWithOptions(api, cfg, SecurityOptions{MCPEnabled: true})
	request := newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"encrypt","arguments":{"profileId":"dev","plaintext":"synthetic"},`+mcpMeta+`}}`)
	request.Header.Set("Mcp-Name", "encrypt")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
	var envelope apimodels.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != apimodels.ApiErrorCodeNotReady {
		t.Fatalf("error code = %q, want not_ready", envelope.Error.Code)
	}
}

func TestMCPToolCallEncryptUsesDecodedNameAndExplicitSuccessFields(t *testing.T) {
	handler := mcpOffHandler()
	request := newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"encrypt","arguments":{"profileId":"dev","plaintext":"synthetic"},`+mcpMeta+`}}`)
	request.Header.Set("Mcp-Name", "=?base64?"+base64.StdEncoding.EncodeToString([]byte("encrypt"))+"?=")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope["result"].(map[string]any)
	if result["resultType"] != "complete" || result["isError"] != false {
		t.Fatalf("success fields = %#v", result)
	}
	structured := result["structuredContent"].(map[string]any)
	if structured["vaultText"] != "vault-output" {
		t.Fatalf("structuredContent = %#v", structured)
	}
	content := result["content"].([]any)[0].(map[string]any)
	if content["type"] != "text" || !strings.Contains(content["text"].(string), "vault-output") {
		t.Fatalf("content = %#v", content)
	}
}

func TestMCPKnownToolInputSchemaFailureIsToolError(t *testing.T) {
	handler := mcpOffHandler()
	request := newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"encrypt","arguments":{"profileId":"dev","unexpected":"value"},`+mcpMeta+`}}`)
	request.Header.Set("Mcp-Name", "encrypt")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("isError = %#v, want true in result %#v", result["isError"], result)
	}
	if _, ok := result["structuredContent"]; ok {
		t.Fatalf("structuredContent present on tool argument error: %#v", result["structuredContent"])
	}
}

func TestMCPHeaderRejectionDoesNotReadBody(t *testing.T) {
	handler := mcpOffHandler()
	body := &trackingReader{}
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Add("MCP-Protocol-Version", "2026-07-28")
	request.Header.Add("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "server/discover")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	if body.read {
		t.Fatal("body was read before singleton header validation")
	}
}

func TestMCPNativeScopePreflightBeforeBodyRead(t *testing.T) {
	handler, issuer, _ := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", &trackingReader{})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "encrypt")
	request.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", "vaultsmith.profile.read"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("MCP disabled status = %d, want 404 before auth", response.Code)
	}

	cfg := config.AuthConfig{
		Mode:    config.AuthModeNative,
		OIDC:    config.OIDCConfig{IssuerURL: issuer.server.URL, PublicBaseURL: "https://vaultsmith.example.test", GroupsClaim: "groups"},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", Secure: true},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
	}
	verifier, err := authn.NewAccessTokenVerifier(request.Context(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &authn.Authenticator{Config: cfg, Access: verifier}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{Auth: authenticator, AuthConfig: cfg})
	enabled := WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator, MCPEnabled: true})
	body := &trackingReader{}
	blocked := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
	blocked.Header = request.Header.Clone()
	response = httptest.NewRecorder()

	enabled.ServeHTTP(response, blocked)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", response.Code, response.Body.String())
	}
	if body.read {
		t.Fatal("body was read before MCP scope preflight")
	}
	if !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="vaultsmith.encrypt"`) {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestMCPMissingCredentialChallengeUsesExactHeaderScope(t *testing.T) {
	_, issuer, _ := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", &trackingReader{})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "encrypt")
	cfg := config.AuthConfig{
		Mode:    config.AuthModeNative,
		OIDC:    config.OIDCConfig{IssuerURL: issuer.server.URL, PublicBaseURL: "https://vaultsmith.example.test", GroupsClaim: "groups"},
		Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session", Secure: true},
		CSRF:    config.CSRFConfig{Secret: "01234567890123456789012345678901"},
	}
	verifier, err := authn.NewAccessTokenVerifier(request.Context(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &authn.Authenticator{Config: cfg, Access: verifier}
	api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{Auth: authenticator, AuthConfig: cfg})
	enabled := WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: authenticator, MCPEnabled: true})
	response := httptest.NewRecorder()

	enabled.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="vaultsmith.encrypt"`) {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestMCPResultsCarryExactSDKServerInfoMetadata(t *testing.T) {
	previousVersion := version.Version
	version.Version = "1.2.3"
	t.Cleanup(func() { version.Version = previousVersion })
	handler := mcpOffHandler()
	requests := []struct {
		method string
		body   string
	}{
		{method: "server/discover", body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + mcpMeta + `}}`},
		{method: "tools/list", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + mcpMeta + `}}`},
		{method: "tools/call", body: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_profiles","arguments":{},` + mcpMeta + `}}`},
	}
	for _, test := range requests {
		t.Run(test.method, func(t *testing.T) {
			request := newMCPRequest(test.method, test.body)
			if test.method == "tools/call" {
				request.Header.Set("Mcp-Name", "list_profiles")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			var envelope struct {
				Result map[string]json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if _, found := envelope.Result["serverInfo"]; found {
				t.Fatal("serverInfo was emitted as a top-level result field")
			}
			var metadata map[string]json.RawMessage
			if err := json.Unmarshal(envelope.Result["_meta"], &metadata); err != nil {
				t.Fatalf("decode result metadata: %v", err)
			}
			var implementation mcp.Implementation
			if err := json.Unmarshal(metadata[mcp.MetaKeyServerInfo], &implementation); err != nil {
				t.Fatalf("decode SDK server info: %v", err)
			}
			if implementation.Name != "vaultsmith" || implementation.Version != "1.2.3" {
				t.Fatalf("server info = %#v", implementation)
			}
		})
	}
}

func TestMCPRejectsInvalidJSONRPCMessageClasses(t *testing.T) {
	handler := mcpOffHandler()
	invalid := []string{
		`{"jsonrpc":"2.0","id":true,"method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","id":{},"method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","id":[],"method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","id":null,"method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","method":"server/discover","params":{` + mcpMeta + `}}`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + mcpMeta + `}}]`,
	}
	for index, body := range invalid {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newMCPRequest("server/discover", body))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("case %d status = %d, want 400: %s", index, response.Code, response.Body.String())
		}
		var envelope struct {
			Error mcpJSONRPCError `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != mcpErrorInvalidRequest {
			t.Fatalf("case %d error = %#v, %v", index, envelope.Error, err)
		}
	}
}

func TestMCPMetaValidatesSDKClientFields(t *testing.T) {
	handler := mcpOffHandler()
	invalidMeta := []string{
		`"io.modelcontextprotocol/clientCapabilities":[]`,
		`"io.modelcontextprotocol/clientCapabilities":{"sampling":true}`,
		`"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":"client"`,
		`"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"","version":"1"}`,
		`"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"client","version":""}`,
	}
	for index, fields := range invalidMeta {
		body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` + fields + `}}}`
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newMCPRequest("server/discover", body))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("case %d status = %d, want 400: %s", index, response.Code, response.Body.String())
		}
	}
}

func TestMCPMetaRejectsMalformedProtocolVersionAsInvalidParams(t *testing.T) {
	handler := mcpOffHandler()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":true,"io.modelcontextprotocol/clientCapabilities":{}}}}`
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, newMCPRequest("server/discover", body))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error mcpJSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != mcpErrorInvalidParams {
		t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorInvalidParams)
	}
}

func TestMCPMixedCaseBase64MarkerRemainsLiteral(t *testing.T) {
	value := "=?BASE64?ZW5jcnlwdA==?="
	decoded, err := decodeMCPNameHeader(value)
	if err != nil || decoded != value {
		t.Fatalf("decodeMCPNameHeader() = %q, %v; want literal", decoded, err)
	}
}

func TestMCPMalformedLowercaseBase64MarkerIsRejected(t *testing.T) {
	for _, value := range []string{"=?base64?ZW5jcnlwdA==", "=?base64?not-base64?="} {
		if decoded, err := decodeMCPNameHeader(value); err == nil {
			t.Fatalf("decodeMCPNameHeader(%q) = %q, nil; want error", value, decoded)
		}
	}
}

func TestMCPMutationPolicyDenialIsGenericHTTPForbidden(t *testing.T) {
	handler, issuer, executor := bearerHTTPFixtureWithMCP(t, true)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rotate","arguments":{"sourceProfileId":"dev","destinationProfileId":"dev","vaultText":"synthetic"},` + mcpMeta + `}}`
	request := newMCPRequest("tools/call", body)
	request.Header.Set("Mcp-Name", "rotate")
	request.Header.Set("Authorization", "Bearer "+issuer.tokenWithGroups(t, "https://vaultsmith.example.test", "vaultsmith.rotate", []string{}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", response.Code, response.Body.String())
	}
	if challenge := response.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty for policy denial", challenge)
	}
	if response.Body.String() != "{\"error\":{\"code\":\"forbidden\",\"message\":\"operation is not permitted\"}}\n" {
		t.Fatalf("body = %q, want generic forbidden envelope", response.Body.String())
	}
	if executor.called {
		t.Fatal("executor was called after policy denial")
	}
}

func TestMCPMalformedJSONReturnsParseError(t *testing.T) {
	handler := mcpOffHandler()
	request := newMCPRequest("server/discover", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error mcpJSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != mcpErrorParse {
		t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorParse)
	}
}

func TestMCPMetaAcceptsNamedExtensions(t *testing.T) {
	handler := mcpOffHandler()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"com.example/clientTrace":"synthetic","progressToken":1}}}`
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, newMCPRequest("server/discover", body))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestMCPMetaAcceptsProtocolValidEmptyNames(t *testing.T) {
	handler := mcpOffHandler()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"com.example/":true,"":false}}}`
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, newMCPRequest("server/discover", body))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestMCPMetaRejectsInvalidExtensionName(t *testing.T) {
	handler := mcpOffHandler()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"bad prefix/value":true}}}`
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, newMCPRequest("server/discover", body))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error mcpJSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != mcpErrorInvalidParams {
		t.Fatalf("error code = %d, want %d", envelope.Error.Code, mcpErrorInvalidParams)
	}
}

func TestMCPSessionHeaderIsIgnoredAndNeverEchoed(t *testing.T) {
	handler := mcpOffHandler()
	request := newMCPRequest("server/discover", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+mcpMeta+`}}`)
	request.Header.Set("Mcp-Session-Id", "synthetic-session")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("Mcp-Session-Id = %q, want empty", got)
	}
}

func TestMCPHeaderValidationPrecedesCredentialDispatch(t *testing.T) {
	called := false
	cfg := config.AuthConfig{Mode: config.AuthModeNative}
	handler := WrapSecurityWithOptions(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), cfg, SecurityOptions{Auth: &authn.Authenticator{Config: cfg}, MCPEnabled: true})
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", &trackingReader{})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	if called {
		t.Fatal("credential dispatch reached inner handler after malformed MCP headers")
	}
}

func TestMCPHeadersAreParsedOnceBeforeCredentialDispatch(t *testing.T) {
	cfg := config.AuthConfig{Mode: config.AuthModeOff}
	observed := mcpHeaders{}
	handler := WrapSecurityWithOptions(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var ok bool
		observed, ok = mcpHeadersFromRequest(r)
		if !ok {
			t.Fatal("parsed MCP headers missing from request context")
		}
		// Mutation after preflight must not change the parsed values used by the facade.
		r.Header.Set("Mcp-Method", "resources/list")
	}), cfg, SecurityOptions{MCPEnabled: true})
	request := newMCPRequest("tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	request.Header.Set("Mcp-Name", "=?base64?"+base64.StdEncoding.EncodeToString([]byte("encrypt"))+"?=")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if observed.protocolVersion != mcpProtocolVersion || observed.method != "tools/call" || observed.toolName != "encrypt" {
		t.Fatalf("observed headers = %#v", observed)
	}
}

func TestCanonicalBearerScopePreflightOccursBeforeHandler(t *testing.T) {
	wrapped, issuer, _ := bearerHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/profiles/dev/encrypt", &trackingReader{})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeProfileRead))
	response := httptest.NewRecorder()

	wrapped.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="vaultsmith.encrypt"`) {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}
