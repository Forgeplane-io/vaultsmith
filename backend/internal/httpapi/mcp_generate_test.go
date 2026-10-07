package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

var mcpGenerateToolOrder = [...]string{
	"generate_password",
	"generate_token",
	"generate_ssh_keypair",
	"generate_age_identity",
	"generate_x509_csr",
}

func mcpGenerateOffHandler(t *testing.T, generator *recordingMaterialGenerator, executor *generateTestExecutor, admission *vaultservice.Admission) http.Handler {
	t.Helper()
	cfg := config.AuthConfig{Mode: config.AuthModeOff}
	return WrapSecurityWithOptions(generateTestHandler(t, generator, executor, admission), cfg, SecurityOptions{MCPEnabled: true})
}

func newMCPGenerateRequest(name, arguments string) *http.Request {
	body := `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `,` + mcpMeta + `}}`
	request := newMCPRequest("tools/call", body)
	request.Header.Set("Mcp-Name", name)
	return request
}

func TestMCPGenerateToolsSealEveryKindWithoutTextLeak(t *testing.T) {
	tests := []struct {
		name         string
		tool         string
		arguments    string
		kind         string
		secretFormat string
		hasPublic    bool
		effective    string
	}{
		{name: "password", tool: "generate_password", arguments: `{"profileId":"dev"}`, kind: "password", secretFormat: "password_ascii"},
		{name: "password explicit parameters", tool: "generate_password", arguments: `{"profileId":"dev","length":40,"lowercase":false,"uppercase":true,"digits":true,"symbols":true,"minLowercase":0,"minUppercase":2,"minDigits":3,"minSymbols":4,"excludeAmbiguous":true}`, kind: "password", secretFormat: "password_ascii", effective: `{"length":40,"lowercase":false,"uppercase":true,"digits":true,"symbols":true,"minLowercase":0,"minUppercase":2,"minDigits":3,"minSymbols":4,"excludeAmbiguous":true}`},
		{name: "token", tool: "generate_token", arguments: `{"profileId":"dev","encoding":"hex","bytes":16}`, kind: "token", secretFormat: "token_hex"},
		{name: "SSH", tool: "generate_ssh_keypair", arguments: `{"profileId":"dev","algorithm":"ed25519"}`, kind: "ssh_keypair", secretFormat: "openssh_private_key", hasPublic: true},
		{name: "age", tool: "generate_age_identity", arguments: `{"profileId":"dev"}`, kind: "age_identity", secretFormat: "age_x25519_identity", hasPublic: true},
		{name: "X.509", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ecdsa_p256","subject":{"commonName":"service.example"}}`, kind: "x509_csr", secretFormat: "pkcs8_private_key_pem", hasPublic: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := mcpGenerateOffHandler(t, generator, executor, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, newMCPGenerateRequest(test.tool, test.arguments))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if len(generator.calls) != 1 || string(generator.calls[0]) != test.kind || len(executor.plaintext) != 1 {
				t.Fatalf("generator/executor calls = %#v/%d, want %q/1", generator.calls, len(executor.plaintext), test.kind)
			}
			var envelope map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			result := envelope["result"].(map[string]any)
			if result["resultType"] != "complete" || result["ttlMs"] != float64(0) || result["cacheScope"] != "private" || result["isError"] != false {
				t.Fatalf("result metadata = %#v", result)
			}
			content := result["content"].([]any)
			if len(content) != 1 || content[0].(map[string]any)["type"] != "text" || content[0].(map[string]any)["text"] != mcpGenerateResultText {
				t.Fatalf("content = %#v", content)
			}
			structured := result["structuredContent"].(map[string]any)
			if structured["kind"] != test.kind || structured["profileId"] != "dev" {
				t.Fatalf("structured identity = %#v", structured)
			}
			if test.effective != "" {
				var expected map[string]any
				if err := json.Unmarshal([]byte(test.effective), &expected); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(structured["effectiveParameters"], expected) {
					t.Fatalf("effective parameters = %#v, want %#v", structured["effectiveParameters"], expected)
				}
			}
			secret := structured["secret"].(map[string]any)
			if secret["format"] != test.secretFormat || secret["vaultText"] == "" {
				t.Fatalf("structured secret = %#v", secret)
			}
			_, publicPresent := structured["public"]
			if publicPresent != test.hasPublic {
				t.Fatalf("public present = %v, want %v: %#v", publicPresent, test.hasPublic, structured)
			}
			if strings.Count(response.Body.String(), `"structuredContent"`) != 1 {
				t.Fatalf("structuredContent delivery count is not one: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), executor.plaintext[0]) {
				t.Fatal("MCP response exposed generated private material")
			}
		})
	}
}

func TestMCPGenerateTypedArgumentsRejectAmbiguousInputBeforeGeneration(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		arguments string
	}{
		{name: "password unknown field", tool: "generate_password", arguments: `{"profileId":"dev","alphabet":"custom"}`},
		{name: "password null", tool: "generate_password", arguments: `{"profileId":"dev","symbols":null}`},
		{name: "null profile", tool: "generate_token", arguments: `{"profileId":null}`},
		{name: "REST wrapper", tool: "generate_token", arguments: `{"profileId":"dev","parameters":{"bytes":32}}`},
		{name: "REST discriminator", tool: "generate_token", arguments: `{"profileId":"dev","kind":"token"}`},
		{name: "token wrong integer type", tool: "generate_token", arguments: `{"profileId":"dev","bytes":"32"}`},
		{name: "SSH missing algorithm", tool: "generate_ssh_keypair", arguments: `{"profileId":"dev"}`},
		{name: "age extra field", tool: "generate_age_identity", arguments: `{"profileId":"dev","algorithm":"x25519"}`},
		{name: "X.509 unknown nested field", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","subject":{"commonName":"service.example","unexpected":"value"}}`},
		{name: "X.509 null array item", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","sans":{"dnsNames":[null]}}`},
		{name: "unpaired profile surrogate", tool: "generate_token", arguments: `{"profileId":"\ud800"}`},
		{name: "unpaired token encoding surrogate", tool: "generate_token", arguments: `{"profileId":"dev","encoding":"\ud800"}`},
		{name: "unpaired SSH algorithm surrogate", tool: "generate_ssh_keypair", arguments: `{"profileId":"dev","algorithm":"\ud800"}`},
		{name: "unpaired X.509 algorithm surrogate", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"\ud800","subject":{"commonName":"service.example"}}`},
		{name: "unpaired identity surrogate", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","subject":{"commonName":"\ud800"}}`},
		{name: "unpaired identity array surrogate", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","sans":{"dnsNames":["\ud800"]}}`},
		{name: "duplicate argument", tool: "generate_token", arguments: `{"profileId":"dev","profileId":"other"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := mcpGenerateOffHandler(t, generator, executor, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, newMCPGenerateRequest(test.tool, test.arguments))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want MCP tool error 200: %s", response.Code, response.Body.String())
			}
			var envelope map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			result := envelope["result"].(map[string]any)
			if result["isError"] != true || result["structuredContent"] != nil {
				t.Fatalf("tool error result = %#v", result)
			}
			if len(generator.calls) != 0 || len(executor.plaintext) != 0 {
				t.Fatalf("generator/executor calls = %#v/%d, want none", generator.calls, len(executor.plaintext))
			}
		})
	}
}

func TestMCPGenerateFailuresAreGenericAndDoNotExposePrivateMaterial(t *testing.T) {
	tests := []struct {
		name         string
		arguments    string
		generatorErr error
		executorErr  error
	}{
		{name: "generator", arguments: `{"profileId":"dev"}`, generatorErr: errors.New("sensitive-generator-detail")},
		{name: "Vault encrypt", arguments: `{"profileId":"dev"}`, executorErr: errors.New("sensitive-profile-password-detail")},
		{name: "invalid bounded parameter", arguments: `{"profileId":"dev","bytes":1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			generator.err = test.generatorErr
			executor := &generateTestExecutor{err: test.executorErr}
			handler := mcpGenerateOffHandler(t, generator, executor, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, newMCPGenerateRequest("generate_token", test.arguments))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want MCP tool error 200: %s", response.Code, response.Body.String())
			}
			var envelope map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			result := envelope["result"].(map[string]any)
			if result["isError"] != true || result["structuredContent"] != nil {
				t.Fatalf("tool error result = %#v", result)
			}
			content := result["content"].([]any)
			if len(content) != 1 || content[0].(map[string]any)["text"] != mcpTextToolFailure {
				t.Fatalf("tool error content = %#v", content)
			}
			for _, sensitive := range []string{"sensitive-generator-detail", "sensitive-profile-password-detail"} {
				if strings.Contains(response.Body.String(), sensitive) {
					t.Fatalf("response exposed %q", sensitive)
				}
			}
			if len(executor.plaintext) != 0 && strings.Contains(response.Body.String(), executor.plaintext[0]) {
				t.Fatal("failure response exposed generated private material")
			}
		})
	}
}

func TestMCPGenerateBearerScopePreflightRejectsEveryToolBeforeBodyRead(t *testing.T) {
	handler, issuer, _ := bearerHTTPFixtureWithMCP(t, true)
	warm := httptest.NewRequest(http.MethodGet, "https://vaultsmith.example.test/api/v1/profiles", nil)
	warm.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeProfileRead))
	warmResponse := httptest.NewRecorder()
	handler.ServeHTTP(warmResponse, warm)
	if warmResponse.Code != http.StatusOK {
		t.Fatalf("JWKS warm-up status = %d, want 200", warmResponse.Code)
	}
	for _, name := range mcpGenerateToolOrder {
		t.Run(name, func(t *testing.T) {
			body := &trackingReader{}
			request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
			ctx := &deadlineTrackingContext{Context: request.Context()}
			request = request.WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
			request.Header.Set("Mcp-Method", "tools/call")
			request.Header.Set("Mcp-Name", name)
			request.Header.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeProfileRead))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusForbidden || body.read {
				t.Fatalf("status/read = %d/%v, want 403/false: %s", response.Code, body.read, response.Body.String())
			}
			if !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="vaultsmith.encrypt"`) {
				t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
			}
			if ctx.queried {
				t.Fatal("application deadline was installed before the Generate scope challenge")
			}
		})
	}
}

func TestMCPGeneratePolicyDenialPrecedesParameterValidation(t *testing.T) {
	handler, issuer, executor := bearerHTTPFixtureWithMCP(t, true)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	token := issuer.tokenWithGroups(t, "https://vaultsmith.example.test", vaultservice.ScopeEncrypt, []string{})
	for _, test := range []struct {
		name, tool, arguments string
	}{
		{name: "token", tool: "generate_token", arguments: `{"profileId":"dev","bytes":1}`},
		{name: "subject overflow", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","subject":{"organization":[` + strings.Repeat(`"synthetic",`, 8) + `"synthetic"]}}`},
		{name: "mixed SAN overflow", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","sans":{"dnsNames":[` + strings.Repeat(`"example.test",`, 63) + `"example.test"],"uris":["https://example.test"]}}`},
		{name: "large subject overflow", tool: "generate_x509_csr", arguments: `{"profileId":"dev","algorithm":"ed25519","subject":{"organization":[` + strings.Repeat(`"x",`, 65535) + `"x"]}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range []string{"REST", "MCP"} {
				// The large fixture intentionally exceeds REST's separate ceiling.
				if transport == "REST" && test.name == "large subject overflow" {
					continue
				}
				request := newMCPGenerateRequest(test.tool, test.arguments)
				if transport == "REST" {
					kind := "x509_csr"
					if test.tool == "generate_token" {
						kind = "token"
					}
					parameters := strings.TrimPrefix(test.arguments, `{"profileId":"dev",`)
					request = httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(`{"kind":"`+kind+`","profileId":"dev","parameters":{`+parameters+`}`))
					request.Header.Set("Content-Type", "application/json")
				}
				// Use the real TLS listener, retaining the fixture's configured token audience.
				headers := request.Header
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+request.URL.Path, request.Body)
				if err != nil {
					t.Fatal(err)
				}
				request.Header = headers
				request.Header.Set("Authorization", "Bearer "+token)
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal("native request failed")
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || response.StatusCode != http.StatusForbidden || response.Header.Get("WWW-Authenticate") != "" || string(body) != "{\"error\":{\"code\":\"forbidden\",\"message\":\"operation is not permitted\"}}\n" {
					t.Fatalf("%s status = %d, want unchanged policy denial 403 with no challenge", transport, response.StatusCode)
				}
				t.Logf("transport=%s status=%d policy_denied=true", transport, response.StatusCode)
			}
		})
	}
	if executor.called {
		t.Fatal("executor was called after policy denial")
	}
}

func TestMCPGenerateX509CombinedSANBudget(t *testing.T) {
	for _, transport := range []string{"REST", "MCP"} {
		for _, count := range []int{64, 65} {
			t.Run(fmt.Sprintf("%s/%d", transport, count), func(t *testing.T) {
				sans := map[string][]string{}
				for i := range 16 { // Four equal groups reach ADR 0002's combined limit.
					sans["dnsNames"] = append(sans["dnsNames"], fmt.Sprintf("host%d.example.test", i))
					sans["ipAddresses"] = append(sans["ipAddresses"], fmt.Sprintf("192.0.2.%d", i+1))
					sans["emailAddresses"] = append(sans["emailAddresses"], fmt.Sprintf("user%d@example.test", i))
					sans["uris"] = append(sans["uris"], fmt.Sprintf("https://example.test/%d", i))
				}
				if count == 65 {
					sans["uris"] = append(sans["uris"], "https://example.test/extra")
				}
				raw, err := json.Marshal(map[string]any{"algorithm": "ed25519", "sans": sans})
				if err != nil {
					t.Fatal(err)
				}
				generator := newRecordingMaterialGenerator()
				executor := &generateTestExecutor{}
				handler := generateTestHandler(t, generator, executor, nil)
				request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(`{"kind":"x509_csr","profileId":"dev","parameters":`+string(raw)+`}`))
				request.Header.Set("Content-Type", "application/json")
				if transport == "MCP" {
					handler = mcpGenerateOffHandler(t, generator, executor, nil)
					request = newMCPGenerateRequest("generate_x509_csr", `{"profileId":"dev",`+string(raw[1:]))
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if count == 65 {
					wantStatus, wantText := http.StatusBadRequest, "generation parameters are invalid"
					if transport == "MCP" {
						wantStatus, wantText = http.StatusOK, mcpTextToolFailure
					}
					if response.Code != wantStatus || !strings.Contains(response.Body.String(), wantText) || strings.Contains(response.Body.String(), "structuredContent") || len(executor.plaintext) != 0 || len(generator.calls) != 0 {
						t.Fatalf("combined overflow status/generator/encrypt calls = %d/%d/%d, want %d/0/0", response.Code, len(generator.calls), len(executor.plaintext), wantStatus)
					}
				} else {
					var payload map[string]json.RawMessage
					if response.Code != http.StatusOK || len(executor.plaintext) != 1 || json.Unmarshal(response.Body.Bytes(), &payload) != nil {
						t.Fatal("combined boundary was not sealed")
					}
					if transport == "MCP" {
						var result struct {
							StructuredContent map[string]json.RawMessage `json:"structuredContent"`
						}
						if json.Unmarshal(payload["result"], &result) != nil {
							t.Fatal("invalid MCP result")
						}
						payload = result.StructuredContent
					}
					var public struct {
						CSRPEM string `json:"csrPem"`
					}
					if json.Unmarshal(payload["public"], &public) != nil {
						t.Fatal("missing public result")
					}
					block, _ := pem.Decode([]byte(public.CSRPEM))
					if block == nil {
						t.Fatal("invalid CSR PEM")
					}
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 64 {
						t.Fatal("combined CSR boundary was truncated or invalid")
					}
				}
				t.Logf("entries=%d status=%d encrypt_calls=%d", count, response.Code, len(executor.plaintext))
			})
		}
	}
}

func TestMCPGeneratePreflightAndSaturationDoNotReadBody(t *testing.T) {
	t.Run("not ready", func(t *testing.T) {
		cfg := config.AuthConfig{Mode: config.AuthModeOff}
		handler := WrapSecurityWithOptions(&Handler{}, cfg, SecurityOptions{MCPEnabled: true})
		body := &trackingReader{}
		request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		request.Header.Set("Mcp-Method", "tools/call")
		request.Header.Set("Mcp-Name", "generate_password")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusServiceUnavailable || body.read {
			t.Fatalf("status/read = %d/%v, want 503/false: %s", response.Code, body.read, response.Body.String())
		}
	})

	t.Run("all Generate tools omit retry", func(t *testing.T) {
		admission, err := vaultservice.NewAdmission(1)
		if err != nil {
			t.Fatal(err)
		}
		held, err := admission.TryAcquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()
		generator := newRecordingMaterialGenerator()
		executor := &generateTestExecutor{}
		handler := mcpGenerateOffHandler(t, generator, executor, admission)
		for _, name := range mcpGenerateToolOrder {
			t.Run(name, func(t *testing.T) {
				body := &trackingReader{}
				request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Accept", "application/json, text/event-stream")
				request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
				request.Header.Set("Mcp-Method", "tools/call")
				request.Header.Set("Mcp-Name", name)
				response := httptest.NewRecorder()

				handler.ServeHTTP(response, request)

				if response.Code != http.StatusServiceUnavailable || body.read {
					t.Fatalf("status/read = %d/%v, want 503/false: %s", response.Code, body.read, response.Body.String())
				}
				if response.Header().Get("Retry-After") != "" {
					t.Fatalf("Retry-After = %q, want absent", response.Header().Get("Retry-After"))
				}
			})
		}
		if len(generator.calls) != 0 || len(executor.plaintext) != 0 {
			t.Fatalf("generator/executor calls = %#v/%d, want none", generator.calls, len(executor.plaintext))
		}

		body := &trackingReader{}
		request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/mcp", body)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		request.Header.Set("Mcp-Method", "tools/call")
		request.Header.Set("Mcp-Name", "encrypt")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || body.read || response.Header().Get("Retry-After") != "1" {
			t.Fatalf("legacy saturation status/read/retry = %d/%v/%q", response.Code, body.read, response.Header().Get("Retry-After"))
		}
	})
}

func TestMCPGenerateRetainsEightMiBTransportCeiling(t *testing.T) {
	baseBody := `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"generate_token","arguments":{"profileId":"dev"},` + mcpMeta + `}}`
	for _, test := range []struct {
		name   string
		size   int
		status int
		calls  int
	}{
		{name: "exact MCP limit", size: MaxRequestBodyBytes, status: http.StatusOK, calls: 1},
		{name: "one byte over MCP limit", size: MaxRequestBodyBytes + 1, status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.size <= MaxGenerateRequestBodyBytes {
				t.Fatalf("test size %d does not exceed REST Generate limit", test.size)
			}
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := mcpGenerateOffHandler(t, generator, executor, nil)
			body := baseBody + strings.Repeat(" ", test.size-len(baseBody))
			request := newMCPRequest("tools/call", body)
			request.Header.Set("Mcp-Name", "generate_token")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status || len(generator.calls) != test.calls {
				t.Fatalf("status/calls = %d/%d, want %d/%d: %s", response.Code, len(generator.calls), test.status, test.calls, response.Body.String())
			}
		})
	}
}
