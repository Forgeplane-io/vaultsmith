package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

// Assert the public scrape, not the registry's internal maps. Every unrelated
// operation/outcome must remain zero, including discovery and arbitrary names.
func assertOperationScrape(t *testing.T, handler http.Handler, operation, outcome string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", response.Code)
	}
	body := response.Body.String()
	for _, op := range []string{"encrypt", "decrypt", "rotate", "generate", "legacy", "verify"} {
		count := 0
		if op == operation {
			count = 1
		}
		line := fmt.Sprintf("vaultsmith_operation_duration_seconds_count{operation=%q} %d\n", op, count)
		if !strings.Contains(body, line) {
			t.Errorf("missing scrape line %s", strings.TrimSpace(line))
		}
		for _, result := range []string{"success", "invalid_request", "unauthorized", "forbidden", "not_found", "unavailable", "busy", "failed"} {
			value := 0
			if op == operation && result == outcome {
				value = 1
			}
			line := fmt.Sprintf("vaultsmith_operation_requests_total{operation=%q,outcome=%q} %d\n", op, result, value)
			if !strings.Contains(body, line) {
				t.Errorf("missing scrape line %s", strings.TrimSpace(line))
			}
		}
	}
	for _, excluded := range []string{"profileId", "synthetic", "repository", "revision", "selector", "generate_token", "caller", "password", "ciphertext"} {
		if strings.Contains(body, excluded) {
			t.Errorf("scrape contains excluded label/value %q", excluded)
		}
	}
}

func TestMCPGenerateOperationScrapes(t *testing.T) {
	tools := []struct{ name, arguments string }{
		{"generate_password", `{"profileId":"dev"}`},
		{"generate_token", `{"profileId":"dev"}`},
		{"generate_ssh_keypair", `{"profileId":"dev","algorithm":"ed25519"}`},
		{"generate_age_identity", `{"profileId":"dev"}`},
		{"generate_x509_csr", `{"profileId":"dev","algorithm":"ed25519","subject":{"commonName":"synthetic.example"}}`},
	}
	for _, tool := range tools {
		for _, outcome := range []string{"success", "failed", "invalid_request"} {
			t.Run(tool.name+"/"+outcome, func(t *testing.T) {
				generator := newRecordingMaterialGenerator()
				arguments := tool.arguments
				if outcome == "failed" {
					generator.err = errors.New("synthetic failure detail")
				} else if outcome == "invalid_request" {
					arguments = `{}`
				}
				handler := mcpGenerateOffHandler(t, generator, nil, nil)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, newMCPGenerateRequest(tool.name, arguments))
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), fmt.Sprintf(`"isError":%t`, outcome != "success")) {
					t.Fatalf("unexpected tool result (HTTP %d)", response.Code)
				}
				assertOperationScrape(t, handler, "generate", outcome)
			})
		}
	}
}

func TestMCPOperationEarlyExitScrapes(t *testing.T) {
	for _, name := range []string{"malformed body", "name mismatch", "busy", "cancelled", "scope denial", "unknown tool", "list profiles", "discovery", "tools list", "invalid headers"} {
		t.Run(name, func(t *testing.T) {
			admission, err := vaultservice.NewAdmission(1)
			if err != nil {
				t.Fatal(err)
			}
			handler := mcpGenerateOffHandler(t, nil, nil, admission)
			request := newMCPGenerateRequest("generate_token", `{"profileId":"dev"}`)
			operation, outcome, status := "generate", "invalid_request", http.StatusBadRequest
			switch name {
			case "malformed body":
				request = newMCPRequest("tools/call", `{`)
				request.Header.Set("Mcp-Name", "generate_token")
			case "name mismatch":
				request.Header.Set("Mcp-Name", "generate_password")
			case "busy":
				lease, err := admission.TryAcquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
				outcome, status = "busy", http.StatusServiceUnavailable
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				request = request.WithContext(ctx)
				outcome, status = "unavailable", http.StatusServiceUnavailable
			case "scope denial":
				actor, err := caller.NewBearer("https://issuer.synthetic.test", "synthetic-subject", nil, []string{vaultservice.ScopeProfileRead})
				if err != nil {
					t.Fatal(err)
				}
				request = request.WithContext(contextWithCaller(request.Context(), actor))
				outcome, status = "forbidden", http.StatusForbidden
			case "unknown tool":
				request = newMCPGenerateRequest("synthetic_unknown_tool", `{}`)
				operation = ""
			case "list profiles":
				request = newMCPGenerateRequest("list_profiles", `{}`)
				operation, status = "", http.StatusOK
			case "discovery", "tools list":
				method := "server/discover"
				if name == "tools list" {
					method = "tools/list"
				}
				request = newMCPRequest(method, `{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":{`+mcpMeta+`}}`)
				operation, status = "", http.StatusOK
			case "invalid headers":
				request.Header.Del("MCP-Protocol-Version")
				operation = ""
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != status {
				t.Fatalf("status = %d, want %d", response.Code, status)
			}
			assertOperationScrape(t, handler, operation, outcome)
		})
	}
}

func TestMCPVaultOperationScrapes(t *testing.T) {
	for _, tool := range []string{"encrypt", "decrypt", "rotate", "verify_rotation_attestation"} {
		for _, outcome := range []string{"success", "failed", "invalid_request", "unavailable", "busy"} {
			if tool == "verify_rotation_attestation" && (outcome == "success" || outcome == "failed") {
				continue // Real successful verification is covered by smoke-attestation.
			}
			if outcome == "unavailable" && tool != "rotate" && tool != "verify_rotation_attestation" {
				continue // Only attestation operations have disabled-feature errors.
			}
			if outcome == "busy" && tool != "verify_rotation_attestation" {
				continue // Operation admission saturation is covered above.
			}
			t.Run(tool+"/"+outcome, func(t *testing.T) {
				manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
				service, executor := newHTTPAttestationService(t, manager, outcome != "unavailable", 1)
				input := httpSyntheticVaultText(t, "synthetic input", "synthetic password", "source")
				executor.value = httpSyntheticVaultText(t, "synthetic output", "synthetic password", "destination")
				if outcome == "failed" {
					executor.err = errors.New("synthetic executor failure")
				}
				if outcome == "busy" {
					lease, err := service.VerifierAdmission().TryAcquire(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer lease.Release()
				}
				arguments := `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":` + mustJSON(t, input) + `}`
				switch tool {
				case "encrypt":
					arguments = `{"profileId":"source","plaintext":"synthetic input"}`
				case "decrypt":
					arguments = `{"profileId":"source","vaultText":` + mustJSON(t, input) + `}`
				case "verify_rotation_attestation":
					arguments = `{"attestation":{},"inputVaultText":"","outputVaultText":""}`
				}
				if outcome == "invalid_request" {
					arguments = `{}`
				}
				if outcome == "unavailable" && tool != "verify_rotation_attestation" {
					arguments = strings.TrimSuffix(arguments, "}") + `,"attestation":{}}`
				}
				handler := WrapSecurityWithOptions(attestationHTTPHandler(t, service), config.AuthConfig{Mode: config.AuthModeOff}, SecurityOptions{MCPEnabled: true})
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, newMCPGenerateRequest(tool, arguments))
				if outcome == "busy" {
					if response.Code != http.StatusServiceUnavailable {
						t.Fatalf("busy status = %d, want 503", response.Code)
					}
				} else if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), fmt.Sprintf(`"isError":%t`, outcome != "success")) {
					t.Fatalf("unexpected tool result (HTTP %d)", response.Code)
				}
				operation := tool
				if tool == "verify_rotation_attestation" {
					operation = "verify"
				}
				assertOperationScrape(t, handler, operation, outcome)
			})
		}
	}
}
