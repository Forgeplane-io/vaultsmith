package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type mcpAdmissionReader struct {
	io.Reader
	reads  int
	onRead func()
}

func (r *mcpAdmissionReader) Read(p []byte) (int, error) {
	r.reads++
	r.onRead()
	return r.Reader.Read(p)
}

func mcpValidVerificationBody(t *testing.T) string {
	t.Helper()
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	input := httpSyntheticVaultText(t, "synthetic input", "synthetic source password", "source")
	output := httpSyntheticVaultText(t, "synthetic output", "synthetic destination password", "destination")
	inputDigest, err := attestation.InputDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest, err := attestation.OutputDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := manager.Sign(attestation.RotationClaims{
		Version: attestation.SupportedVersion, Issuer: manager.Issuer(), IssuedAt: "2026-08-15T12:34:56Z",
		Operation: "rotate", SourceProfileID: "source", DestinationProfileID: "destination",
		Input:  attestation.Digest{Algorithm: "sha-256", Value: inputDigest},
		Output: attestation.Digest{Algorithm: "sha-256", Value: outputDigest},
	})
	if err != nil {
		t.Fatal(err)
	}
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"verify_rotation_attestation","arguments":` +
		mustJSON(t, httpVerifyRequest{Attestation: signed, InputVaultText: input, OutputVaultText: output}) + `,` + mcpMeta + `}}`
}

func TestMCPVerificationAdmission(t *testing.T) {
	validBody := mcpValidVerificationBody(t)
	for _, mode := range []config.AuthMode{config.AuthModeOff, config.AuthModeNative} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := config.AuthConfig{Mode: mode, OIDC: config.OIDCConfig{PublicBaseURL: "https://vaultsmith.example.test", GroupsClaim: "groups"}}
			var auth *authn.Authenticator
			var issuer *bearerIssuerFixture
			var authorization string
			if mode == config.AuthModeNative {
				issuer = newBearerIssuerFixture(t)
				cfg.OIDC.IssuerURL = issuer.server.URL
				verifier, err := authn.NewAccessTokenVerifier(t.Context(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, issuer.server.Client())
				if err != nil {
					t.Fatal(err)
				}
				auth = &authn.Authenticator{Config: cfg, Access: verifier}
				authorization = "Bearer " + issuer.token(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeAttestationVerify)
			}
			for _, state := range []struct {
				name, code string
				enabled    bool
				ready      bool
			}{
				{name: "disabled", code: "feature_unavailable"},
				{name: "unavailable", enabled: true, code: "attestation_unavailable"},
				{name: "ready", enabled: true, ready: true},
			} {
				t.Run(state.name, func(t *testing.T) {
					validResult := `"valid":true`
					if state.code != "" {
						validResult = `"code":"` + state.code + `"`
					}
					type admissionCase struct {
						name, body, result string
						status             int
						saturated          bool
						denied             bool
					}
					tests := []admissionCase{
						{name: "saturated", body: "{", status: http.StatusServiceUnavailable, result: `"code":"attestation_busy"`, saturated: true},
						{name: "available", body: validBody, status: http.StatusOK, result: validResult},
						{name: "malformed JSON", body: "{", status: http.StatusBadRequest, result: `"code":-32700`},
						{name: "invalid UTF8", body: "\xff", status: http.StatusBadRequest, result: `"code":-32700`},
						{name: "invalid arguments", body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"verify_rotation_attestation","arguments":{},` + mcpMeta + `}}`, status: http.StatusOK, result: `"isError":true`},
						{name: "too large", body: strings.Repeat(" ", maxMCPVerifyBodyBytes+1), status: http.StatusRequestEntityTooLarge, result: `"code":-32600`},
					}
					if issuer != nil {
						tests = append(tests,
							admissionCase{name: "unauthenticated", body: validBody, status: http.StatusUnauthorized, result: `"code":"unauthorized"`, saturated: true, denied: true},
							admissionCase{name: "insufficient scope", body: validBody, status: http.StatusForbidden, result: `"code":"forbidden"`, saturated: true, denied: true},
						)
					}
					for _, test := range tests {
						t.Run(test.name, func(t *testing.T) {
							manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
							manager.ready = state.ready
							// One fixture slot makes saturation deterministic; production capacity is unchanged.
							service, executor := newHTTPAttestationService(t, manager, state.enabled, 1)
							api := NewWithDependencies(nil, nil, Dependencies{Service: service, Auth: auth, AuthConfig: cfg})
							handler := WrapSecurityWithOptions(api, cfg, SecurityOptions{Auth: auth, MCPEnabled: true})
							var held []*vaultservice.Lease
							pool := service.Admission()
							if test.saturated {
								pool = service.VerifierAdmission()
							}
							for range pool.Capacity() {
								lease, err := pool.TryAcquire(t.Context())
								if err != nil {
									t.Fatal(err)
								}
								t.Cleanup(lease.Release)
								held = append(held, lease)
							}
							wantVerifierUse, wantOperationUse := 0, service.Admission().Capacity()
							if test.saturated {
								wantVerifierUse, wantOperationUse = service.VerifierAdmission().Capacity(), 0
							}
							retainedWithoutAdmission, operationUseChanged := false, false
							body := &mcpAdmissionReader{Reader: strings.NewReader(test.body), onRead: func() {
								retainedWithoutAdmission = retainedWithoutAdmission || service.VerifierAdmission().InUse() != 1
								operationUseChanged = operationUseChanged || service.Admission().InUse() != wantOperationUse
							}}
							request := newMCPRequest("tools/call", "")
							request.Body = io.NopCloser(body)
							request.Header.Set("Mcp-Name", "verify_rotation_attestation")
							if authorization != "" {
								request.Header.Set("Authorization", authorization)
							}
							if test.name == "unauthenticated" {
								request.Header.Del("Authorization")
							} else if test.name == "insufficient scope" {
								request.Header.Set("Authorization", "Bearer "+issuer.token(t, cfg.OIDC.PublicBaseURL, vaultservice.ScopeProfileRead))
							}
							response := httptest.NewRecorder()
							handler.ServeHTTP(response, request)
							if response.Code != test.status || !strings.Contains(response.Body.String(), test.result) {
								t.Errorf("HTTP %d, want %d with error/result class %s", response.Code, test.status, test.result)
							}
							if test.saturated && !test.denied && response.Header().Get("Retry-After") != "1" {
								t.Error("busy response must have Retry-After: 1")
							}
							if test.name == "insufficient scope" && !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="vaultsmith.attestation.verify"`) {
								t.Error("scope denial must challenge for vaultsmith.attestation.verify")
							}
							if test.denied && service.VerifierAdmission().Rejections() != 0 {
								t.Error("authentication/scope must precede admission")
							}
							if (test.saturated && body.reads != 0) || (!test.saturated && body.reads == 0) || retainedWithoutAdmission || operationUseChanged {
								t.Errorf("body reads=%d, without verifier admission=%t, operation admission changed=%t", body.reads, retainedWithoutAdmission, operationUseChanged)
							}
							if service.VerifierAdmission().InUse() != wantVerifierUse || service.Admission().InUse() != wantOperationUse || len(executor.calls) != 0 {
								t.Error("verification leaked admission, released a held lease, or called Vault")
							}
							if test.name == "available" {
								outcome := "success"
								if state.code != "" {
									outcome = "unavailable"
									if !strings.Contains(response.Body.String(), `"isError":true`) {
										t.Error("unavailable verification must remain a structured tool error")
									}
								}
								assertOperationScrape(t, api, "verify", outcome)
							}
							t.Logf("status=%d body_reads=%d verifier_in_use=%d operation_in_use=%d result_class=%s", response.Code, body.reads, service.VerifierAdmission().InUse(), service.Admission().InUse(), test.result)
							for _, lease := range held {
								lease.Release()
							}
							lease, err := service.VerifierAdmission().TryAcquire(t.Context())
							if err != nil {
								t.Fatalf("verifier capacity not restored: %v", err)
							}
							lease.Release()
						})
					}
				})
			}
		})
	}
}

func TestMCPVerificationAdmissionBodyCancellation(t *testing.T) {
	for _, state := range []struct {
		name           string
		enabled, ready bool
	}{
		{name: "disabled"},
		{name: "unavailable", enabled: true},
		{name: "ready", enabled: true, ready: true},
	} {
		t.Run(state.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
				manager.ready = state.ready
				service, _ := newHTTPAttestationService(t, manager, state.enabled, 1)
				handler := WrapSecurityWithOptions(attestationHTTPHandler(t, service), config.AuthConfig{Mode: config.AuthModeOff}, SecurityOptions{MCPEnabled: true})
				body := newContextBlockingBody()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				request := newMCPRequest("tools/call", "").WithContext(ctx)
				request.Body = body
				request.Header.Set("Mcp-Name", "verify_rotation_attestation")
				response := httptest.NewRecorder()
				done := make(chan struct{})
				go func() {
					defer close(done)
					handler.ServeHTTP(response, request)
				}()
				synctest.Wait()
				select {
				case <-body.started:
				default:
					t.Error("body read did not start")
				}
				if service.VerifierAdmission().InUse() != 1 || service.Admission().InUse() != 0 {
					t.Error("body retention must hold verifier admission only")
				}
				cancel()
				synctest.Wait()
				<-done
				if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"temporarily_unavailable"`) {
					t.Errorf("cancelled body read HTTP %d, want 503 temporarily_unavailable", response.Code)
				}
				if service.VerifierAdmission().InUse() != 0 || service.Admission().InUse() != 0 {
					t.Error("cancellation leaked admission")
				}
				t.Logf("status=%d result_class=temporarily_unavailable verifier_in_use=%d operation_in_use=%d", response.Code, service.VerifierAdmission().InUse(), service.Admission().InUse())
			})
		})
	}
}
