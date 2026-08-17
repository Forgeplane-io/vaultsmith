package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/generate"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type recordingMaterialGenerator struct {
	delegate *generate.Generator
	err      error
	calls    []vaultservice.GenerateKind
}

func newRecordingMaterialGenerator() *recordingMaterialGenerator {
	return &recordingMaterialGenerator{delegate: generate.New()}
}

func (g *recordingMaterialGenerator) GeneratePassword(parameters generate.PasswordParameters) (generate.PasswordResult, error) {
	g.calls = append(g.calls, vaultservice.GenerateKindPassword)
	if g.err != nil {
		return generate.PasswordResult{}, g.err
	}
	return g.delegate.GeneratePassword(parameters)
}

func (g *recordingMaterialGenerator) GenerateToken(parameters generate.TokenParameters) (generate.TokenResult, error) {
	g.calls = append(g.calls, vaultservice.GenerateKindToken)
	if g.err != nil {
		return generate.TokenResult{}, g.err
	}
	return g.delegate.GenerateToken(parameters)
}

func (g *recordingMaterialGenerator) GenerateSSHKeyPair(parameters generate.SSHKeyPairParameters) (generate.SSHKeyPairResult, error) {
	g.calls = append(g.calls, vaultservice.GenerateKindSSHKeyPair)
	if g.err != nil {
		return generate.SSHKeyPairResult{}, g.err
	}
	return g.delegate.GenerateSSHKeyPair(parameters)
}

func (g *recordingMaterialGenerator) GenerateAgeIdentity() (generate.AgeIdentityResult, error) {
	g.calls = append(g.calls, vaultservice.GenerateKindAgeIdentity)
	if g.err != nil {
		return generate.AgeIdentityResult{}, g.err
	}
	return g.delegate.GenerateAgeIdentity()
}

func (g *recordingMaterialGenerator) GenerateX509CSR(parameters generate.X509CSRParameters) (generate.X509CSRResult, error) {
	g.calls = append(g.calls, vaultservice.GenerateKindX509CSR)
	if g.err != nil {
		return generate.X509CSRResult{}, g.err
	}
	return g.delegate.GenerateX509CSR(parameters)
}

type generateTestExecutor struct {
	err       error
	plaintext []string
}

type denyingGenerateAuthorizer struct {
	calls int
}

func (a *denyingGenerateAuthorizer) Evaluate(_ caller.Caller, checks []authz.Check) ([]bool, error) {
	a.calls++
	return make([]bool, len(checks)), nil
}

type generateTestProfileExecutor struct {
	owner     *generateTestExecutor
	profileID string
}

func (e *generateTestExecutor) ForProfile(profileID string) (vaultservice.ProfileExecutor, error) {
	return &generateTestProfileExecutor{owner: e, profileID: profileID}, nil
}

func (e *generateTestProfileExecutor) Encrypt(_ context.Context, value string) (string, error) {
	e.owner.plaintext = append(e.owner.plaintext, value)
	if e.owner.err != nil {
		return "", e.owner.err
	}
	return ansiblevault.Encrypt([]byte(value), []byte("synthetic-generate-test-password"), e.profileID)
}

func (*generateTestProfileExecutor) Decrypt(context.Context, string) (string, error) {
	return "", errors.New("decrypt is not used by Generate")
}

func generateTestHandler(t *testing.T, generator *recordingMaterialGenerator, executor *generateTestExecutor, admission *vaultservice.Admission) http.Handler {
	t.Helper()
	if generator == nil {
		generator = newRecordingMaterialGenerator()
	}
	if executor == nil {
		executor = &generateTestExecutor{}
	}
	if admission == nil {
		var err error
		admission, err = vaultservice.NewAdmission(1)
		if err != nil {
			t.Fatal(err)
		}
	}
	profiles := []vaultservice.Profile{{ID: "dev", Label: "Development"}}
	service := vaultservice.NewWithOptions(profiles, executor, nil, admission, vaultservice.ServiceOptions{Generator: generator})
	return NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		executor,
		Dependencies{AuthConfig: config.AuthConfig{Mode: config.AuthModeOff}, Service: service},
	)
}

func TestGenerateEndpointSealsEveryMaterialKind(t *testing.T) {
	tests := []struct {
		name          string
		kind          string
		body          string
		secretFormat  string
		hasPublic     bool
		wantEffective map[string]any
	}{
		{
			name: "password", kind: "password",
			body: `{"kind":"password","profileId":"dev","parameters":{}}`, secretFormat: "password_ascii",
			wantEffective: map[string]any{
				"length": float64(32), "lowercase": true, "uppercase": true, "digits": true, "symbols": false,
				"minLowercase": float64(1), "minUppercase": float64(1), "minDigits": float64(1), "minSymbols": float64(0),
				"excludeAmbiguous": false,
			},
		},
		{
			name: "token", kind: "token",
			body: `{"kind":"token","profileId":"dev","parameters":{"encoding":"hex","bytes":16}}`, secretFormat: "token_hex",
			wantEffective: map[string]any{"encoding": "hex", "bytes": float64(16)},
		},
		{
			name: "SSH", kind: "ssh_keypair",
			body: `{"kind":"ssh_keypair","profileId":"dev","parameters":{"algorithm":"ed25519"}}`, secretFormat: "openssh_private_key", hasPublic: true,
			wantEffective: map[string]any{"algorithm": "ed25519"},
		},
		{
			name: "age", kind: "age_identity",
			body: `{"kind":"age_identity","profileId":"dev","parameters":{}}`, secretFormat: "age_x25519_identity", hasPublic: true,
			wantEffective: map[string]any{"algorithm": "x25519"},
		},
		{
			name: "X.509", kind: "x509_csr",
			body: `{"kind":"x509_csr","profileId":"dev","parameters":{"algorithm":"ecdsa_p256","subject":{"commonName":"service.example"}}}`, secretFormat: "pkcs8_private_key_pem", hasPublic: true,
			wantEffective: map[string]any{"algorithm": "ecdsa_p256"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := generateTestHandler(t, generator, executor, nil)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept-Encoding", "gzip")
			request.Header.Set("If-None-Match", `"opaque-prior-result"`)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if len(generator.calls) != 1 || string(generator.calls[0]) != test.kind || len(executor.plaintext) != 1 {
				t.Fatalf("generator/executor calls = %#v/%d, want %q/1", generator.calls, len(executor.plaintext), test.kind)
			}
			var payload map[string]any
			if err := jsonUnmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["kind"] != test.kind || payload["profileId"] != "dev" {
				t.Fatalf("response identity = %#v", payload)
			}
			effective, ok := payload["effectiveParameters"].(map[string]any)
			if !ok {
				t.Fatalf("effective parameters = %#v", payload["effectiveParameters"])
			}
			if !reflect.DeepEqual(effective, test.wantEffective) {
				t.Fatalf("effective parameters = %#v, want %#v", effective, test.wantEffective)
			}
			secret, ok := payload["secret"].(map[string]any)
			if !ok || secret["format"] != test.secretFormat || secret["vaultText"] == "" {
				t.Fatalf("secret response = %#v", payload["secret"])
			}
			_, publicPresent := payload["public"]
			if publicPresent != test.hasPublic {
				t.Fatalf("public present = %v, want %v: %#v", publicPresent, test.hasPublic, payload)
			}
			if strings.Contains(response.Body.String(), executor.plaintext[0]) {
				t.Fatal("response exposed generated private material")
			}
			for _, forbidden := range []string{"plaintext", "value", "privateKey", "identity"} {
				if _, present := payload[forbidden]; present {
					t.Fatalf("response contains forbidden field %q: %#v", forbidden, payload)
				}
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("security headers = %#v", response.Header())
			}
			if response.Header().Get("Content-Encoding") != "" || response.Header().Get("ETag") != "" {
				t.Fatalf("compression/ETag headers = %q/%q", response.Header().Get("Content-Encoding"), response.Header().Get("ETag"))
			}
		})
	}
}

func TestGenerateStrictDecoderRejectsAmbiguousInputBeforeGeneration(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "top-level duplicate", body: `{"kind":"token","Kind":"password","profileId":"dev","parameters":{}}`},
		{name: "nested duplicate", body: `{"kind":"token","profileId":"dev","parameters":{"bytes":16,"Bytes":32}}`},
		{name: "unknown nested field", body: `{"kind":"password","profileId":"dev","parameters":{"alphabet":"custom"}}`},
		{name: "explicit null", body: `{"kind":"password","profileId":"dev","parameters":{"symbols":null}}`},
		{name: "missing algorithm", body: `{"kind":"ssh_keypair","profileId":"dev","parameters":{}}`},
		{name: "age parameters not empty", body: `{"kind":"age_identity","profileId":"dev","parameters":{"algorithm":"x25519"}}`},
		{name: "empty subject", body: `{"kind":"x509_csr","profileId":"dev","parameters":{"algorithm":"ed25519","subject":{}}}`},
		{name: "unpaired identity surrogate", body: `{"kind":"x509_csr","profileId":"dev","parameters":{"algorithm":"ed25519","subject":{"commonName":"\ud800"}}}`},
		{name: "null array item", body: `{"kind":"x509_csr","profileId":"dev","parameters":{"algorithm":"ed25519","sans":{"dnsNames":[null]}}}`},
		{name: "trailing JSON", body: `{"kind":"token","profileId":"dev","parameters":{}}{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := generateTestHandler(t, generator, executor, nil)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
			if len(generator.calls) != 0 || len(executor.plaintext) != 0 {
				t.Fatalf("generator/executor calls = %#v/%d, want none", generator.calls, len(executor.plaintext))
			}
		})
	}

	generator := newRecordingMaterialGenerator()
	executor := &generateTestExecutor{}
	handler := generateTestHandler(t, generator, executor, nil)
	raw := append([]byte(`{"kind":"token","profileId":"dev","parameters":{"encoding":"`), 0xff)
	raw = append(raw, []byte(`"}}`)...)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(generator.calls) != 0 || len(executor.plaintext) != 0 {
		t.Fatalf("invalid UTF-8 response/calls = %d/%#v/%d: %s", response.Code, generator.calls, len(executor.plaintext), response.Body.String())
	}
}

func TestGenerateStringDecoderAcceptsPairedSurrogatesAndLiteralEscapes(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "paired surrogate", raw: `"\ud83d\ude00"`, want: "😀"},
		{name: "literal backslash u", raw: `"\\ud800"`, want: `\ud800`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeGenerateString(json.RawMessage(test.raw))
			if err != nil || got != test.want {
				t.Fatalf("decodeGenerateString() = %q, %v, want %q", got, err, test.want)
			}
		})
	}
}

func TestGenerateHasDedicatedBodyCeiling(t *testing.T) {
	base := `{"kind":"token","profileId":"dev","parameters":{}}`
	for _, test := range []struct {
		name   string
		size   int
		status int
		calls  int
	}{
		{name: "exact limit", size: MaxGenerateRequestBodyBytes, status: http.StatusOK, calls: 1},
		{name: "one byte over", size: MaxGenerateRequestBodyBytes + 1, status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &generateTestExecutor{}
			handler := generateTestHandler(t, generator, executor, nil)
			body := base + strings.Repeat(" ", test.size-len(base))
			request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status || len(generator.calls) != test.calls {
				t.Fatalf("response/calls = %d/%d, want %d/%d: %s", response.Code, len(generator.calls), test.status, test.calls, response.Body.String())
			}
		})
	}
}

func TestGenerateRejectsIdempotencyAndSaturationBeforeBodyRead(t *testing.T) {
	t.Run("idempotency key", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			value string
		}{
			{name: "value", value: "do-not-log-this-value"},
			{name: "empty"},
		} {
			t.Run(test.name, func(t *testing.T) {
				generator := newRecordingMaterialGenerator()
				executor := &generateTestExecutor{}
				handler := generateTestHandler(t, generator, executor, nil)
				body := &trackingReader{}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", body)
				request.Header.Set("Content-Type", "application/json")
				request.Header["Idempotency-Key"] = []string{test.value}
				response := httptest.NewRecorder()

				handler.ServeHTTP(response, request)

				if response.Code != http.StatusBadRequest || body.read || len(generator.calls) != 0 || len(executor.plaintext) != 0 {
					t.Fatalf("response/read/calls = %d/%v/%#v/%d", response.Code, body.read, generator.calls, len(executor.plaintext))
				}
				if strings.Contains(response.Body.String(), "do-not-log") {
					t.Fatal("idempotency value was reflected")
				}
			})
		}
	})

	t.Run("saturation", func(t *testing.T) {
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
		handler := generateTestHandler(t, generator, executor, admission)
		body := &trackingReader{}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", body)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusServiceUnavailable || body.read || len(generator.calls) != 0 || len(executor.plaintext) != 0 {
			t.Fatalf("response/read/calls = %d/%v/%#v/%d", response.Code, body.read, generator.calls, len(executor.plaintext))
		}
		if response.Header().Get("Retry-After") != "" {
			t.Fatalf("Retry-After = %q, want absent", response.Header().Get("Retry-After"))
		}
	})
}

func TestGenerateFailuresAreAtomicAndGeneric(t *testing.T) {
	tests := []struct {
		name          string
		generatorErr  error
		executorErr   error
		wantExecCalls int
	}{
		{name: "generator", generatorErr: errors.New("generator failure with private-canary")},
		{name: "Vault encryption", executorErr: errors.New("vault failure with private-canary"), wantExecCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			generator.err = test.generatorErr
			executor := &generateTestExecutor{err: test.executorErr}
			handler := generateTestHandler(t, generator, executor, nil)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(`{"kind":"token","profileId":"dev","parameters":{}}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnprocessableEntity || len(executor.plaintext) != test.wantExecCalls {
				t.Fatalf("response/executor calls = %d/%d: %s", response.Code, len(executor.plaintext), response.Body.String())
			}
			if response.Body.String() != `{"error":{"code":"operation_failed","message":"vault operation failed"}}`+"\n" || strings.Contains(response.Body.String(), "private-canary") {
				t.Fatalf("unsafe failure response = %q", response.Body.String())
			}
		})
	}
}

func TestGeneratePolicyDenialPrecedesGeneration(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	executor := &generateTestExecutor{}
	authorizer := &denyingGenerateAuthorizer{}
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []vaultservice.Profile{{ID: "dev", Label: "Development"}}
	service := vaultservice.NewWithOptions(profiles, executor, authorizer, admission, vaultservice.ServiceOptions{Generator: generator})
	handler := NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		executor,
		Dependencies{AuthConfig: config.AuthConfig{Mode: config.AuthModeNative}, Service: service},
	)
	actor, err := caller.NewSession("https://issuer.example", "subject", []string{"operators"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(`{"kind":"token","profileId":"dev","parameters":{}}`))
	request = request.WithContext(contextWithCaller(request.Context(), actor))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || authorizer.calls != 1 {
		t.Fatalf("response/policy calls = %d/%d: %s", response.Code, authorizer.calls, response.Body.String())
	}
	if len(generator.calls) != 0 || len(executor.plaintext) != 0 {
		t.Fatalf("generator/executor calls = %#v/%d, want none", generator.calls, len(executor.plaintext))
	}
}

func TestGenerateCredentialGuardsRejectBeforeBodyRead(t *testing.T) {
	t.Run("native bearer scope", func(t *testing.T) {
		handler, issuer, _ := bearerHTTPFixture(t)
		for _, test := range []struct {
			name          string
			authorization string
			status        int
		}{
			{name: "missing", status: http.StatusUnauthorized},
			{name: "insufficient", authorization: "Bearer " + issuer.token(t, "https://vaultsmith.example.test", "vaultsmith.decrypt"), status: http.StatusForbidden},
		} {
			t.Run(test.name, func(t *testing.T) {
				body := &trackingReader{}
				request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/generate", body)
				request.Header.Set("Content-Type", "application/json")
				if test.authorization != "" {
					request.Header.Set("Authorization", test.authorization)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != test.status || body.read {
					t.Fatalf("response/read = %d/%v: %s", response.Code, body.read, response.Body.String())
				}
				if !strings.Contains(response.Header().Get("WWW-Authenticate"), "vaultsmith.encrypt") {
					t.Fatalf("challenge = %q", response.Header().Get("WWW-Authenticate"))
				}
			})
		}
	})

	t.Run("native session CSRF", func(t *testing.T) {
		handler, authenticator, cfg, _, _ := nativeHTTPFixture(t)
		session := seedNativeSession(t, authenticator)
		body := &trackingReader{}
		request := httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/generate", body)
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: session})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || body.read {
			t.Fatalf("response/read = %d/%v: %s", response.Code, body.read, response.Body.String())
		}
	})

	t.Run("off mode authorization", func(t *testing.T) {
		generator := newRecordingMaterialGenerator()
		executor := &generateTestExecutor{}
		cfg := config.AuthConfig{Mode: config.AuthModeOff}
		handler := WrapSecurityWithOptions(generateTestHandler(t, generator, executor, nil), cfg, SecurityOptions{})
		body := &trackingReader{}
		request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test/api/v1/generate", body)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer ignored")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || body.read || len(generator.calls) != 0 {
			t.Fatalf("response/read/calls = %d/%v/%#v: %s", response.Code, body.read, generator.calls, response.Body.String())
		}
	})
}

// Keep JSON decoding errors local to the test without coupling assertions to
// generated union helpers.
func jsonUnmarshal(raw []byte, target any) error {
	return json.Unmarshal(raw, target)
}
