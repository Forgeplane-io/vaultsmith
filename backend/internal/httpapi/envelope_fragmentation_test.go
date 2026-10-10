package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type envelopeProfileResolver struct{ configured config.Executor }

func (r envelopeProfileResolver) ForProfile(id string) (vaultservice.ProfileExecutor, error) {
	return r.configured.ForProfile(id)
}

// Exercise real loopback HTTP, service admission, configured crypto executors,
// and MCP dispatch. Failures must disclose neither values nor claims, release
// admission, and permit a completed decrypt/rotation immediately afterward.
func TestFragmentedEnvelopeTransports(t *testing.T) {
	configured, err := config.LoadJSON(`[{"id":"dev","label":"Synthetic","passwordEnv":"SYNTHETIC_VAULT_PASSWORD"}]`, func(name string) (string, bool) {
		return "synthetic-password", name == "SYNTHETIC_VAULT_PASSWORD"
	})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := vaultservice.NewAdmission(1) // One slot makes any leaked lease observable on the next request.
	if err != nil {
		t.Fatal(err)
	}
	auth := config.AuthConfig{Mode: config.AuthModeOff}
	handler := NewWithDependencies([]Profile{{ID: "dev", Label: "Synthetic"}}, envelopeProfileResolver{configured.Executor()}, Dependencies{Admission: admission, AuthConfig: auth})
	server := httptest.NewServer(WrapSecurityWithOptions(handler, auth, SecurityOptions{MCPEnabled: true}))
	defer server.Close()
	valid := httpSyntheticVaultText(t, "synthetic-value", "synthetic-password", "dev")
	const headerPrefix = ansiblevault.Header12Prefix + ";"
	const headerSuffix = "\n00\n"
	fixtures := []struct{ name, value string }{
		{"header", headerPrefix + strings.Repeat(";", MaxVaultTextBytes-len(headerPrefix)-len(headerSuffix)) + headerSuffix},
		{"outer", ansiblevault.Header11 + "\n" + strings.Repeat("0\n", (MaxVaultTextBytes-len(ansiblevault.Header11)-1)/2)},
		{"inner", ansiblevault.Header11 + "\n" + strings.Repeat(strings.Repeat("0a", 40)+"\n", (MaxVaultTextBytes-len(ansiblevault.Header11)-1)/81)},
	}
	for _, transport := range []string{"REST", "MCP"} {
		for _, operation := range []string{"decrypt", "rotate"} {
			for _, fixture := range fixtures {
				t.Run(transport+"/"+operation+"/"+fixture.name, func(t *testing.T) {
					for _, malformed := range []bool{true, false} {
						value := valid
						if malformed {
							value = fixture.value
						}
						args := map[string]any{"vaultText": value}
						path := "/api/v1/profiles/dev/decrypt"
						if operation == "rotate" {
							path = "/api/v1/rotations"
							args["sourceProfileId"], args["destinationProfileId"] = "dev", "dev"
						} else {
							args["profileId"] = "dev"
						}
						var body []byte
						if transport == "MCP" {
							path = "/mcp"
							meta := map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
							body, err = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": operation, "arguments": args, "_meta": meta}})
						} else {
							delete(args, "profileId")
							body, err = json.Marshal(args)
						}
						if err != nil {
							t.Fatal(err)
						}
						request, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("Content-Type", "application/json")
						if transport == "MCP" {
							request.Header.Set("Accept", "application/json, text/event-stream")
							request.Header.Set("MCP-Protocol-Version", "2026-07-28")
							request.Header.Set("Mcp-Method", "tools/call")
							request.Header.Set("Mcp-Name", operation)
						}
						response, err := server.Client().Do(request)
						if err != nil {
							t.Fatal("HTTP request failed")
						}
						data, readErr := io.ReadAll(response.Body)
						response.Body.Close()
						if readErr != nil {
							t.Fatal("HTTP response read failed")
						}
						var result map[string]any
						if err := json.Unmarshal(data, &result); err != nil {
							t.Fatal("invalid response JSON")
						}
						if transport == "MCP" {
							if response.StatusCode != http.StatusOK {
								t.Fatalf("MCP status=%d", response.StatusCode)
							}
							tool, ok := result["result"].(map[string]any)
							if !ok || tool["isError"] != malformed {
								t.Fatal("unexpected MCP result class")
							}
							if malformed {
								if _, ok := tool["structuredContent"]; ok {
									t.Fatal("failure exposes structured result")
								}
								content, ok := tool["content"].([]any)
								if !ok || len(content) != 1 {
									t.Fatal("unexpected MCP failure content")
								}
								message, ok := content[0].(map[string]any)
								if !ok || message["type"] != "text" || message["text"] != "tool call failed" {
									t.Fatal("unsafe MCP failure message")
								}
							} else {
								result, ok = tool["structuredContent"].(map[string]any)
								if !ok {
									t.Fatal("missing completed MCP result")
								}
							}
						} else if malformed {
							if response.StatusCode != http.StatusUnprocessableEntity || string(data) != "{\"error\":{\"code\":\"operation_failed\",\"message\":\"vault operation failed\"}}\n" {
								t.Fatalf("unsafe failure contract: status=%d", response.StatusCode)
							}
						} else if response.StatusCode != http.StatusOK {
							t.Fatalf("REST status=%d", response.StatusCode)
						}
						if malformed {
							if bytes.Contains(data, []byte("synthetic-password")) || bytes.Contains(data, []byte("synthetic-value")) || bytes.Contains(data, []byte("attestation")) {
								t.Fatal("unsafe failure response")
							}
						} else if operation == "decrypt" {
							if result["plaintext"] != "synthetic-value" {
								t.Fatal("decrypt did not complete")
							}
						} else {
							rotated, ok := result["vaultText"].(string)
							if !ok {
								t.Fatal("missing rotation result")
							}
							plain, err := ansiblevault.Decrypt(rotated, []byte("synthetic-password"))
							if err != nil || string(plain) != "synthetic-value" {
								t.Fatal("rotation did not complete")
							}
						}
						if admission.InUse() != 0 {
							t.Fatalf("admission leak: configured=%d observed=%d", admission.Capacity(), admission.InUse())
						}
						t.Logf("malformed=%t status=%d admission_in_use=%d completed=true", malformed, response.StatusCode, admission.InUse())
					}
				})
			}
		}
	}
}
