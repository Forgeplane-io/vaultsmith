package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type blockingReadCloser struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{started: make(chan struct{}), closed: make(chan struct{})}
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockingReadCloser) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestOperationRejectsDuplicateJSONKeys(t *testing.T) {
	tests := []string{
		`{"profileId":"dev","mode":"encrypt","mode":"decrypt","value":"value"}`,
		`{"profileId":"dev","mode":"encrypt","Mode":"decrypt","value":"value"}`,
	}
	for _, body := range tests {
		executor := &fakeExecutor{value: "synthetic-output"}
		handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400: %s", body, response.Code, response.Body.String())
		}
		if len(executor.calls) != 0 {
			t.Fatalf("body %q executed: %#v", body, executor.calls)
		}
	}
}

func TestOperationRejectsInvalidUTF8JSON(t *testing.T) {
	raw := append([]byte(`{"profileId":"dev","mode":"encrypt","value":"`), 0xff)
	raw = append(raw, []byte(`"}`)...)
	executor := &fakeExecutor{value: "synthetic-output"}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
}

func TestOperationRejectsUnsupportedContentEncodingBeforeBodyRead(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "gzip", values: []string{"gzip"}},
		{name: "identity then gzip fields", values: []string{"identity", "gzip"}},
		{name: "gzip then identity fields", values: []string{"gzip", "identity"}},
		{name: "comma list", values: []string{"identity, gzip"}},
		{name: "duplicate identity", values: []string{"identity", "identity"}},
		{name: "empty", values: []string{""}},
		{name: "whitespace", values: []string{" 	"}},
		{name: "trailing comma", values: []string{"identity,"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReader{}
			executor := &fakeExecutor{}
			handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", body)
			request.Header.Set("Content-Type", "application/json")
			request.Header["Content-Encoding"] = append([]string(nil), test.values...)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415: %s", response.Code, response.Body.String())
			}
			if body.read || len(executor.calls) != 0 {
				t.Fatalf("body read/executor calls = %v/%#v, want false/none", body.read, executor.calls)
			}
		})
	}
}

func TestOperationAcceptsSingleIdentityContentEncoding(t *testing.T) {
	executor := &fakeExecutor{value: "synthetic-output"}
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, executor)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"value"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", " identity ")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || len(executor.calls) != 1 {
		t.Fatalf("response/calls = %d/%#v, want 200/one: %s", response.Code, executor.calls, response.Body.String())
	}
}

func TestOperationRejectsUnsupportedAuthorizationSchemeBeforeBodyRead(t *testing.T) {
	tests := []struct {
		name        string
		auth        config.AuthConfig
		headers     []string
		cookie      bool
		cookieValue string
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{name: "off basic", headers: []string{"Basic opaque"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "authorization header is not supported"},
		{name: "off bearer", headers: []string{"Bearer opaque"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "authorization header is not supported"},
		{name: "off empty", headers: []string{""}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "authorization header is not supported"},
		{name: "off whitespace", headers: []string{" 	"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "authorization header is not supported"},
		{name: "off duplicate", headers: []string{"Basic opaque", "Bearer opaque"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "authorization header is not supported"},
		{name: "native basic", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{"Basic opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
		{name: "native bearer", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{"Bearer opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
		{name: "native empty", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{""}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
		{name: "native whitespace", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{" 	"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
		{name: "native duplicate", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{"Basic opaque", "Bearer opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
		{name: "native with session cookie", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{"Basic opaque"}, cookie: true, cookieValue: "opaque-session", wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantMessage: "multiple authentication credentials are not permitted"},
		{name: "native with empty session cookie", auth: config.AuthConfig{Mode: config.AuthModeNative, Session: config.SessionConfig{CookieName: "__Host-vaultsmith_session"}}, headers: []string{"Basic opaque"}, cookie: true, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "request could not be authenticated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReader{}
			executor := &fakeExecutor{}
			handler := NewWithDependencies(
				[]Profile{{ID: "dev", Label: "Development"}},
				executor,
				Dependencies{AuthConfig: test.auth},
			)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", body)
			request.Header.Set("Content-Type", "application/json")
			for _, value := range test.headers {
				request.Header.Add("Authorization", value)
			}
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: test.auth.Session.CookieName, Value: test.cookieValue})
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			var payload struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != test.wantCode || payload.Error.Message != test.wantMessage {
				t.Fatalf("error payload = %#v, %v; want %q/%q", payload, err, test.wantCode, test.wantMessage)
			}
			if body.read || len(executor.calls) != 0 {
				t.Fatalf("body read/executor calls = %v/%#v, want false/none", body.read, executor.calls)
			}
		})
	}
}

func TestSecurityRejectsLegacyAuthorizationBeforeCSRFAndSession(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		cfg         config.AuthConfig
		headers     []string
		cookie      bool
		cookieValue string
		wantStatus  int
		wantCode    string
	}{
		{name: "native operation", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{"Basic opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native operation empty header", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{""}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native operation duplicate header", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{"Basic opaque", "Bearer opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native operation with session", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{"Basic opaque"}, cookie: true, cookieValue: "opaque-session", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "native operation with empty session and basic", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{"Basic opaque"}, cookie: true, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native operation with empty session and empty header", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{""}, cookie: true, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native operation with empty session and duplicate header", method: http.MethodPost, path: "/api/v1/operations", cfg: csrfTestConfig(), headers: []string{"Basic opaque", "Bearer opaque"}, cookie: true, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "native profiles", method: http.MethodGet, path: "/api/v1/profiles", cfg: csrfTestConfig(), headers: []string{"Bearer opaque"}, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "off operation", method: http.MethodPost, path: "/api/v1/operations", cfg: config.AuthConfig{Mode: config.AuthModeOff}, headers: []string{"Bearer opaque"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.cfg.Session.CookieName = "__Host-vaultsmith_session"
			nextCalls := 0
			wrapped := WrapSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalls++
				w.WriteHeader(http.StatusNoContent)
			}), test.cfg)
			body := &trackingReader{}
			request := httptest.NewRequest(test.method, "https://example.test"+test.path, body)
			request.Host = "example.test"
			request.Header["Authorization"] = append([]string(nil), test.headers...)
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: test.cfg.Session.CookieName, Value: test.cookieValue})
			}
			response := httptest.NewRecorder()

			wrapped.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			var payload errorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != test.wantCode {
				t.Fatalf("error payload = %#v, %v; want code %q", payload, err, test.wantCode)
			}
			if body.read || nextCalls != 0 {
				t.Fatalf("body read/next calls = %v/%d, want false/0", body.read, nextCalls)
			}
		})
	}
}

func TestOperationCanceledAdmissionStopsBeforeBodyRead(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	body := &trackingReader{}
	handler := NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		&fakeExecutor{},
		Dependencies{Admission: admission},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", body).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"temporarily_unavailable"`) {
		t.Fatalf("response = %d %s, want 503 temporarily_unavailable", response.Code, response.Body.String())
	}
	if body.read || admission.InUse() != 0 {
		t.Fatalf("body read/in-use = %v/%d, want false/0", body.read, admission.InUse())
	}
}

func TestOperationBodyReadStopsOnCancellation(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{}
	handler := NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		executor,
		Dependencies{Admission: admission},
	)
	body := newBlockingReadCloser()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", nil).WithContext(ctx)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()

	// Two seconds is a deadlock tripwire, not a runtime target. The local read
	// must block until cancellation closes the request body.
	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start reading the admitted request body")
	}
	if admission.InUse() != 1 {
		t.Fatalf("admission in use = %d, want 1 while body read is blocked", admission.InUse())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not stop after request cancellation")
	}
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"temporarily_unavailable"`) {
		t.Fatalf("response = %d %s, want 503 temporarily_unavailable", response.Code, response.Body.String())
	}
	if len(executor.calls) != 0 || admission.InUse() != 0 {
		t.Fatalf("executor calls/in-use = %#v/%d, want none/0", executor.calls, admission.InUse())
	}
}

func TestOperationAdmissionReleasesAfterValidationFailure(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithDependencies(
		[]Profile{{ID: "dev", Label: "Development"}},
		&fakeExecutor{value: "output"},
		Dependencies{Admission: admission},
	)
	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt"}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || admission.InUse() != 0 {
		t.Fatalf("invalid response/in-use = %d/%d, want 400/0", invalidResponse.Code, admission.InUse())
	}

	valid := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"dev","mode":"encrypt","value":"value"}`))
	valid.Header.Set("Content-Type", "application/json")
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK || admission.InUse() != 0 {
		t.Fatalf("valid response/in-use = %d/%d, want 200/0: %s", validResponse.Code, admission.InUse(), validResponse.Body.String())
	}
}

func TestOperationProfileIDsRejectCaseChangedInput(t *testing.T) {
	handler := newHandler([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", strings.NewReader(`{"profileId":"DEV","mode":"encrypt","value":"value"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
}
