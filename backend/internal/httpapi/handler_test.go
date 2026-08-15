package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type fakeExecutor struct {
	value          string
	decryptedValue string
	err            error
	calls          []operationCall
}

type operationCall struct {
	profileID string
	mode      string
	value     string
}

type trackingReader struct {
	read bool
}

func (r *trackingReader) Read([]byte) (int, error) {
	r.read = true
	return 0, io.EOF
}

func newHandler(profiles []Profile, executor Executor) http.Handler {
	return NewWithDependencies(profiles, executor, Dependencies{})
}

func decodeJSONBody[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var body T
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return body
}

type fakeProfileExecutor struct {
	owner     *fakeExecutor
	profileID string
}

func (f *fakeExecutor) ForProfile(profileID string) (vaultservice.ProfileExecutor, error) {
	return &fakeProfileExecutor{owner: f, profileID: profileID}, nil
}

func (f *fakeProfileExecutor) Encrypt(_ context.Context, value string) (string, error) {
	f.owner.calls = append(f.owner.calls, operationCall{profileID: f.profileID, mode: "encrypt", value: value})
	return f.owner.value, f.owner.err
}

func (f *fakeProfileExecutor) Decrypt(_ context.Context, value string) (string, error) {
	f.owner.calls = append(f.owner.calls, operationCall{profileID: f.profileID, mode: "decrypt", value: value})
	if f.owner.decryptedValue != "" {
		return f.owner.decryptedValue, f.owner.err
	}
	return f.owner.value, f.owner.err
}

func TestProfilesEndpoint(t *testing.T) {
	executor := &fakeExecutor{}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	profiles := decodeJSONBody[profilesResponse](t, response).Profiles
	want := apimodels.Profile{Id: "dev", Label: "Development", Capabilities: apimodels.ProfileCapabilities{Encrypt: true, Decrypt: true, RotateSource: true, RotateDestination: true}}
	if len(profiles) != 1 || profiles[0] != want {
		t.Fatalf("profiles = %#v", profiles)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID is missing")
	}
	if strings.Contains(response.Body.String(), "password") {
		t.Fatalf("profiles response contains password-related data: %q", response.Body.String())
	}
}

func TestCanonicalOperationEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		wantBody  string
		wantCalls []operationCall
	}{
		{
			name:     "encrypt",
			path:     "/api/v1/profiles/dev/encrypt",
			body:     `{"plaintext":"fixture-value"}`,
			wantBody: `{"vaultText":"vault-output"}` + "\n",
			wantCalls: []operationCall{
				{profileID: "dev", mode: "encrypt", value: "fixture-value"},
			},
		},
		{
			name:     "decrypt",
			path:     "/api/v1/profiles/dev/decrypt",
			body:     `{"vaultText":"vault-input"}`,
			wantBody: `{"plaintext":"plain-output"}` + "\n",
			wantCalls: []operationCall{
				{profileID: "dev", mode: "decrypt", value: "vault-input"},
			},
		},
		{
			name:     "rotate",
			path:     "/api/v1/rotations",
			body:     `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":"vault-input"}`,
			wantBody: `{"vaultText":"vault-output"}` + "\n",
			wantCalls: []operationCall{
				{profileID: "source", mode: "decrypt", value: "vault-input"},
				{profileID: "destination", mode: "encrypt", value: "plain-output"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{value: "vault-output", decryptedValue: "plain-output"}
			handler := newHandler([]Profile{
				{ID: "dev", Label: "Development"},
				{ID: "source", Label: "Source"},
				{ID: "destination", Label: "Destination"},
			}, executor)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if response.Body.String() != test.wantBody {
				t.Fatalf("body = %q, want %q", response.Body.String(), test.wantBody)
			}
			if !reflect.DeepEqual(executor.calls, test.wantCalls) {
				t.Fatalf("calls = %#v, want %#v", executor.calls, test.wantCalls)
			}
			if response.Header().Get("X-Request-ID") == "" {
				t.Fatal("X-Request-ID is missing")
			}
		})
	}
}

func TestCanonicalOperationValidationBeforeBodyRead(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		status  int
	}{
		{name: "encrypt wrong method", method: http.MethodGet, path: "/api/v1/profiles/dev/encrypt", status: http.StatusMethodNotAllowed},
		{name: "decrypt missing content type", method: http.MethodPost, path: "/api/v1/profiles/dev/decrypt", status: http.StatusUnsupportedMediaType},
		{name: "rotate unsupported encoding", method: http.MethodPost, path: "/api/v1/rotations", headers: map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}, status: http.StatusUnsupportedMediaType},
		{name: "encoded slash profile", method: http.MethodPost, path: "/api/v1/profiles/dev%2Fprod/encrypt", headers: map[string]string{"Content-Type": "application/json"}, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReader{}
			handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{})
			request := httptest.NewRequest(test.method, test.path, body)
			for key, value := range test.headers {
				request.Header.Set(key, value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if body.read {
				t.Fatal("body was read before route/method/header validation completed")
			}
		})
	}
}

func TestProtectedResourceMetadataNativeOnly(t *testing.T) {
	cfg := config.AuthConfig{
		Mode: config.AuthModeNative,
		OIDC: config.OIDCConfig{IssuerURL: "https://id.example.test/realms/vaultsmith", PublicBaseURL: "https://vaultsmith.example.test"},
	}
	handler := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{AuthConfig: cfg})
	request := httptest.NewRequest(http.MethodGet, "https://vaultsmith.example.test/.well-known/oauth-protected-resource", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var body protectedResourceMetadataResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Resource != "https://vaultsmith.example.test" || !reflect.DeepEqual(body.AuthorizationServers, []string{"https://id.example.test/realms/vaultsmith"}) {
		t.Fatalf("metadata = %#v", body)
	}
	if !reflect.DeepEqual(body.ScopesSupported, []string{vaultservice.ScopeProfileRead, vaultservice.ScopeEncrypt, vaultservice.ScopeDecrypt, vaultservice.ScopeRotate, vaultservice.ScopeAttestationVerify}) {
		t.Fatalf("scopes = %#v", body.ScopesSupported)
	}

	off := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{AuthConfig: config.AuthConfig{Mode: config.AuthModeOff}})
	offResponse := httptest.NewRecorder()
	off.ServeHTTP(offResponse, request)
	if offResponse.Code != http.StatusNotFound {
		t.Fatalf("off-mode status = %d, want 404", offResponse.Code)
	}
}

func TestAdmissionMetricsAreBoundedAndUnlabeled(t *testing.T) {
	admission, err := vaultservice.NewAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{Admission: admission})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, line := range []string{
		"vaultsmith_operation_admission_capacity 2\n",
		"vaultsmith_operation_admission_in_use 0\n",
		"vaultsmith_operation_admission_rejections_total 0\n",
	} {
		if !strings.Contains(body, line) {
			t.Fatalf("metrics body = %q, want line %q", body, line)
		}
	}
	if strings.Contains(body, "{") {
		t.Fatalf("metrics contain labels: %q", body)
	}
}

func TestOperationEndpoint(t *testing.T) {
	executor := &fakeExecutor{value: "$ANSIBLE_VAULT;1.1;AES256\nsynthetic"}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"fixture-value"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := decodeJSONBody[valueResponse](t, response).Value; got != executor.value {
		t.Fatalf("value = %q, want %q", got, executor.value)
	}
	if len(executor.calls) != 1 || executor.calls[0] != (operationCall{profileID: "dev", mode: "encrypt", value: "fixture-value"}) {
		t.Fatalf("calls = %#v", executor.calls)
	}
}

func TestRotateOperationEndpoint(t *testing.T) {
	executor := &fakeExecutor{value: "$ANSIBLE_VAULT;1.2;AES256;destination\nsynthetic", decryptedValue: "fixture-value"}
	handler := newHandler([]Profile{
		{ID: "source", Label: "Source"},
		{ID: "destination", Label: "Destination"},
	}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"vault-input"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := decodeJSONBody[valueResponse](t, response).Value; got != executor.value {
		t.Fatalf("value = %q, want %q", got, executor.value)
	}
	wantCalls := []operationCall{
		{profileID: "source", mode: "decrypt", value: "vault-input"},
		{profileID: "destination", mode: "encrypt", value: "fixture-value"},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", executor.calls, wantCalls)
	}
}

func TestOperationFailureIsGeneric(t *testing.T) {
	executor := &fakeExecutor{err: errors.New("wrong password: do-not-leak-this-secret")}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"decrypt","value":"secret-looking-input"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	body := response.Body.String()
	if body != `{"error":{"code":"operation_failed","message":"vault operation failed"}}
` {
		t.Fatalf("body = %q", body)
	}
	if strings.Contains(body, "do-not-leak") || strings.Contains(body, "secret-looking-input") {
		t.Fatalf("error response leaked sensitive data: %q", body)
	}
}

func TestRotateOperationFailureIsGeneric(t *testing.T) {
	executor := &fakeExecutor{err: errors.New("non-UTF-8 plaintext: \xff\xfe")}
	handler := newHandler([]Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"secret-looking-vault"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	body := response.Body.String()
	if body != `{"error":{"code":"operation_failed","message":"vault operation failed"}}
` {
		t.Fatalf("body = %q", body)
	}
	if strings.Contains(body, "non-UTF-8") || strings.Contains(body, "secret-looking-vault") {
		t.Fatalf("error response leaked operation detail: %q", body)
	}
}

func TestValidationAndMethodErrors(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		status      int
	}{
		{name: "profiles post", method: http.MethodPost, path: "/api/v1/profiles", status: http.StatusMethodNotAllowed},
		{name: "operation get", method: http.MethodGet, path: "/api/v1/operations", status: http.StatusMethodNotAllowed},
		{name: "wrong content type", method: http.MethodPost, path: "/api/v1/operations", contentType: "text/plain", body: `{}`, status: http.StatusUnsupportedMediaType},
		{name: "malformed json", method: http.MethodPost, path: "/api/v1/operations", contentType: "application/json", body: `{`, status: http.StatusBadRequest},
		{name: "unknown json field", method: http.MethodPost, path: "/api/v1/operations", contentType: "application/json", body: `{"profileId":"dev","mode":"encrypt","value":"x","password":"secret"}`, status: http.StatusBadRequest},
		{name: "trailing json", method: http.MethodPost, path: "/api/v1/operations", contentType: "application/json", body: `{"profileId":"dev","mode":"encrypt","value":"x"}{}`, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{})
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestRotateValidation(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{name: "missing source", body: `{"mode":"rotate","destinationProfileId":"destination","value":"vault"}`, status: http.StatusBadRequest},
		{name: "missing destination", body: `{"mode":"rotate","sourceProfileId":"source","value":"vault"}`, status: http.StatusBadRequest},
		{name: "mixed profile fields", body: `{"profileId":"source","mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"vault"}`, status: http.StatusBadRequest},
		{name: "unknown source", body: `{"mode":"rotate","sourceProfileId":"missing","destinationProfileId":"destination","value":"vault"}`, status: http.StatusNotFound},
		{name: "unknown destination", body: `{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"missing","value":"vault"}`, status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler([]Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}}, &fakeExecutor{})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestLegacyOperationRequiresPresentNonNullVariantFields(t *testing.T) {
	profiles := []Profile{
		{ID: "dev", Label: "Development"},
		{ID: "source", Label: "Source"},
		{ID: "destination", Label: "Destination"},
	}
	tests := []struct {
		name string
		body string
	}{
		{name: "encrypt missing profile", body: `{"mode":"encrypt","value":"value"}`},
		{name: "encrypt null profile", body: `{"profileId":null,"mode":"encrypt","value":"value"}`},
		{name: "encrypt omitted value", body: `{"profileId":"dev","mode":"encrypt"}`},
		{name: "encrypt null value", body: `{"profileId":"dev","mode":"encrypt","value":null}`},
		{name: "decrypt omitted value", body: `{"profileId":"dev","mode":"decrypt"}`},
		{name: "decrypt null value", body: `{"profileId":"dev","mode":"decrypt","value":null}`},
		{name: "rotate omitted value", body: `{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination"}`},
		{name: "rotate null value", body: `{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":null}`},
		{name: "encrypt variant fields", body: `{"profileId":"dev","sourceProfileId":"","destinationProfileId":null,"mode":"encrypt","value":"value"}`},
		{name: "decrypt variant fields", body: `{"profileId":"dev","sourceProfileId":null,"destinationProfileId":"","mode":"decrypt","value":"value"}`},
		{name: "rotate profile field empty", body: `{"profileId":"","mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"value"}`},
		{name: "rotate profile field null", body: `{"profileId":null,"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"value"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{value: "synthetic-output"}
			handler := newHandler(profiles, executor)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", executor.calls)
			}
		})
	}
}

func TestLegacyOperationAllowsPresentEmptyValue(t *testing.T) {
	executor := &fakeExecutor{value: "synthetic-output"}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":""}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if want := []operationCall{{profileID: "dev", mode: "encrypt", value: ""}}; !reflect.DeepEqual(executor.calls, want) {
		t.Fatalf("executor calls = %#v, want %#v", executor.calls, want)
	}
}

func TestLimitValidation(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		value string
	}{
		{name: "encrypt over limit", mode: "encrypt", value: strings.Repeat("x", MaxPlaintextBytes+1)},
		{name: "decrypt over limit", mode: "decrypt", value: strings.Repeat("x", MaxVaultTextBytes+1)},
		{name: "encrypt multibyte over limit", mode: "encrypt", value: strings.Repeat("🙂", MaxPlaintextBytes/4+1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{})
			body := `{"profileId":"dev","mode":"` + test.mode + `","value":"` + test.value + `"}`
			request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}
}

func TestRotateInputLimitValidation(t *testing.T) {
	handler := newHandler([]Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}}, &fakeExecutor{})
	body := `{"mode":"rotate","sourceProfileId":"source","destinationProfileId":"destination","value":"` + strings.Repeat("x", MaxVaultTextBytes+1) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestJSONBodyLimit(t *testing.T) {
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{})
	body := `{"profileId":"dev","mode":"encrypt","value":"` + strings.Repeat("x", MaxRequestBodyBytes) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestOperationAdmissionRejectsBeforeReadingBody(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	held, err := admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	executor := &fakeExecutor{value: "must-not-run"}
	handler := NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		executor,
		Dependencies{Admission: admission},
	)
	body := &trackingReader{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	if body.read {
		t.Fatal("request body was read while admission was saturated")
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
}

func TestReadiness(t *testing.T) {
	readyHandler := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{})
	notReadyHandler := NewWithDependencies(nil, nil, Dependencies{})
	for _, test := range []struct {
		name    string
		handler http.Handler
		status  int
	}{
		{name: "ready", handler: readyHandler, status: http.StatusOK},
		{name: "not ready", handler: notReadyHandler, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}
