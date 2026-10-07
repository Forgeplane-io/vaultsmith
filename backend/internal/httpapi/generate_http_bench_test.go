package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

// Fixtures exclude construction from measurements. Immediate overflow follows
// ADR 0002's 8/64 bounds; large small-element arrays fit their transport ceiling.
func BenchmarkGenerateX509CollectionOverflow(b *testing.B) {
	for _, transport := range []string{"REST", "MCP"} {
		for _, field := range []struct {
			name, object string
			boundary     int
		}{
			{name: "organization", object: "subject", boundary: 8},
			{name: "dnsNames", object: "sans", boundary: 64},
		} {
			large := 16300 // 65,201 array bytes, below REST's 65,536-byte body ceiling.
			if transport == "MCP" {
				large = 65536 // The representative array is 262,145 bytes, below 8 MiB.
			}
			for _, count := range []int{field.boundary + 1, large} {
				b.Run(fmt.Sprintf("%s/%s/%d", transport, field.name, count), func(b *testing.B) {
					parameters := `{"algorithm":"ed25519","` + field.object + `":{"` + field.name + `":[` + strings.Repeat(`"x",`, count-1) + `"x"]}}`
					body := `{"kind":"x509_csr","profileId":"dev","parameters":` + parameters + `}`
					if transport == "MCP" {
						body = `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"generate_x509_csr","arguments":{"profileId":"dev",` + parameters[1:] + `,` + mcpMeta + `}}`
					}
					cfg := config.AuthConfig{Mode: config.AuthModeOff}
					admission, err := vaultservice.NewAdmission(1)
					if err != nil {
						b.Fatal(err)
					}
					service := vaultservice.NewWithOptions([]vaultservice.Profile{{ID: "dev", Label: "Synthetic development"}}, &generateTestExecutor{}, nil, admission, vaultservice.ServiceOptions{})
					handler := WrapSecurityWithOptions(NewWithDependencies([]Profile{{ID: "dev", Label: "Synthetic development"}}, nil, Dependencies{AuthConfig: cfg, Service: service}), cfg, SecurityOptions{MCPEnabled: true})
					b.ReportAllocs()
					for b.Loop() {
						var request *http.Request
						if transport == "MCP" {
							request = newMCPRequest("tools/call", body)
							request.Header.Set("Mcp-Name", "generate_x509_csr")
						} else {
							request = httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(body))
							request.Header.Set("Content-Type", "application/json")
						}
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						wantStatus, wantMessage := http.StatusBadRequest, "generation parameters are invalid"
						if transport == "MCP" {
							wantStatus, wantMessage = http.StatusOK, mcpTextToolFailure
						}
						if response.Code != wantStatus || !strings.Contains(response.Body.String(), wantMessage) {
							b.Fatalf("overflow status = %d, want %d with safe parameter failure", response.Code, wantStatus)
						}
					}
					lease, err := admission.TryAcquire(context.Background())
					if err != nil {
						b.Fatal("overflow retained the admission lease")
					}
					lease.Release()
				})
			}
		}
	}
}
