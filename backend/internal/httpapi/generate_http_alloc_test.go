//go:build !race

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

// Measure production allocations without race instrumentation: sync.Pool.Put
// deliberately drops one quarter of objects in race builds. Profiling Go 1.27
// attributed 16,400 allocations in this fixture to JSON's pooled decoders,
// rather than retained array elements. Functional controls still run with -race.
func TestGenerateX509CollectionAllocationDoesNotScaleWithCardinality(t *testing.T) {
	for _, transport := range []string{"REST", "MCP"} {
		for _, field := range []struct {
			object, name string
			overflow     int
		}{
			{object: "subject", name: "organization", overflow: 9},
			{object: "sans", name: "dnsNames", overflow: 65},
		} {
			t.Run(transport+"/"+field.name, func(t *testing.T) {
				admission, err := vaultservice.NewAdmission(1)
				if err != nil {
					t.Fatal(err)
				}
				cfg := config.AuthConfig{Mode: config.AuthModeOff}
				handler := WrapSecurityWithOptions(NewWithDependencies([]Profile{{ID: "dev", Label: "Synthetic development"}}, &generateTestExecutor{}, Dependencies{AuthConfig: cfg, Admission: admission}), cfg, SecurityOptions{MCPEnabled: true})
				measure := func(count int) float64 {
					parameters := `{"algorithm":"ed25519","` + field.object + `":{"` + field.name + `":[` + strings.Repeat(`"x",`, count-1) + `"x"]}}`
					body := `{"kind":"x509_csr","profileId":"dev","parameters":` + parameters + `}`
					if transport == "MCP" {
						body = `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"generate_x509_csr","arguments":{"profileId":"dev",` + parameters[1:] + `,` + mcpMeta + `}}`
					}
					return testing.AllocsPerRun(5, func() {
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
						wantStatus, wantText := http.StatusBadRequest, "generation parameters are invalid"
						if transport == "MCP" {
							wantStatus, wantText = http.StatusOK, mcpTextToolFailure
						}
						if response.Code != wantStatus || !strings.Contains(response.Body.String(), wantText) {
							t.Fatal("allocation fixture did not reach the expected parameter failure")
						}
					})
				}
				small := measure(field.overflow)
				largeCount := 16300 // Fits the REST ceiling, including the wrapper.
				if transport == "MCP" {
					largeCount = 65536
				}
				large := measure(largeCount)
				// Before the fix, REST organization grew from 163 to 32,815
				// allocations and MCP from 400 to about 131,670. A 2x tripwire
				// allows transport-buffer growth, not per-element materialization.
				budget := 2 * small
				if large > budget {
					t.Fatalf("element allocation growth budget exceeded: configured=%.0f allocations (2x small=%.0f), observed=%.0f, entries=%d; re-profile transport/decoder before revising this tripwire", budget, small, large, largeCount)
				}
				lease, err := admission.TryAcquire(context.Background())
				if err != nil {
					t.Fatal("overflow retained the admission lease")
				}
				lease.Release()
				t.Logf("entries=%d allocations_small=%.0f allocations_large=%.0f budget=%.0f", largeCount, small, large, budget)
			})
		}
	}
}
