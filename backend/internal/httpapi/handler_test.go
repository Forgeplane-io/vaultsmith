package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeExecutor struct {
	value string
	err   error
	calls []operationCall
}

type operationCall struct {
	profileID            string
	sourceProfileID      string
	destinationProfileID string
	mode                 string
	value                string
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

func (f *fakeExecutor) Execute(profileID, mode, value string) (string, error) {
	f.calls = append(f.calls, operationCall{profileID: profileID, mode: mode, value: value})
	return f.value, f.err
}

func (f *fakeExecutor) Rotate(sourceProfileID, destinationProfileID, value string) (string, error) {
	f.calls = append(f.calls, operationCall{sourceProfileID: sourceProfileID, destinationProfileID: destinationProfileID, mode: "rotate", value: value})
	return f.value, f.err
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
	want := Profile{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{Encrypt: true, Decrypt: true}}
	if len(profiles) != 1 || profiles[0] != want {
		t.Fatalf("profiles = %#v", profiles)
	}
	if strings.Contains(response.Body.String(), "password") {
		t.Fatalf("profiles response contains password-related data: %q", response.Body.String())
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
	executor := &fakeExecutor{value: "$ANSIBLE_VAULT;1.2;AES256;destination\nsynthetic"}
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
	wantCall := operationCall{sourceProfileID: "source", destinationProfileID: "destination", mode: "rotate", value: "vault-input"}
	if len(executor.calls) != 1 || executor.calls[0] != wantCall {
		t.Fatalf("calls = %#v, want %#v", executor.calls, []operationCall{wantCall})
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
