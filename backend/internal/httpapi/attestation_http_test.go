package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type httpSyntheticAttestationManager struct {
	issuer     string
	kid        string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	ready      bool
	signErr    error
	metadata   []byte
	jwks       []byte
}

func newHTTPSyntheticAttestationManager(issuer string) *httpSyntheticAttestationManager {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(publicKey, privateKey[ed25519.SeedSize:])
	return &httpSyntheticAttestationManager{
		issuer:     issuer,
		kid:        "synthetic-key",
		privateKey: privateKey,
		publicKey:  publicKey,
		ready:      true,
		metadata:   []byte(`{"issuer":"https://vaultsmith.synthetic.test","activeKid":"synthetic-key","attestationVersions":[1]}`),
		jwks:       []byte(`{"keys":[{"alg":"Ed25519","crv":"Ed25519","kid":"synthetic-key","kty":"OKP","use":"sig","x":"synthetic-public-only"}]}`),
	}
}

func (m *httpSyntheticAttestationManager) Ready() bool {
	return m != nil && m.ready
}

func (m *httpSyntheticAttestationManager) Issuer() string {
	if m == nil {
		return ""
	}
	return m.issuer
}

func (m *httpSyntheticAttestationManager) Sign(claims attestation.RotationClaims) (attestation.Signed, error) {
	if m.signErr != nil {
		return attestation.Signed{}, m.signErr
	}
	return attestation.Sign(claims, m.kid, m.privateKey)
}

func (m *httpSyntheticAttestationManager) Resolve(issuer, kid string) (attestation.KeyResolution, error) {
	if m == nil || issuer != m.issuer || kid != m.kid {
		return attestation.KeyResolution{}, nil
	}
	publicKey := make(ed25519.PublicKey, len(m.publicKey))
	copy(publicKey, m.publicKey)
	return attestation.KeyResolution{PublicKey: publicKey}, nil
}

func (m *httpSyntheticAttestationManager) MetadataJSON() ([]byte, error) {
	return append([]byte(nil), m.metadata...), nil
}

func (m *httpSyntheticAttestationManager) JWKSJSON() ([]byte, error) {
	return append([]byte(nil), m.jwks...), nil
}

func httpSyntheticVaultText(t *testing.T, plaintext, password, vaultID string) string {
	t.Helper()
	value, err := ansiblevault.Encrypt([]byte(plaintext), []byte(password), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newHTTPAttestationService(t *testing.T, manager *httpSyntheticAttestationManager, enabled bool, verifierCapacity int) (*vaultservice.Service, *fakeExecutor) {
	t.Helper()
	admission, err := vaultservice.NewAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := vaultservice.NewVerifierAdmission(verifierCapacity)
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{}
	service := vaultservice.NewWithOptions(
		[]vaultservice.Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}},
		executor,
		nil,
		admission,
		vaultservice.ServiceOptions{
			AttestationManager: manager,
			AttestationEnabled: enabled,
			VerifierAdmission:  verifier,
		},
	)
	return service, executor
}

func attestationHTTPHandler(t *testing.T, service *vaultservice.Service) http.Handler {
	t.Helper()
	return NewWithDependencies(
		[]Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}},
		&fakeExecutor{},
		Dependencies{Service: service},
	)
}

type httpVerifyRequest struct {
	Attestation     attestation.Signed   `json:"attestation"`
	InputVaultText  string               `json:"inputVaultText"`
	OutputVaultText string               `json:"outputVaultText"`
	ExpectedBinding *attestation.Binding `json:"expectedBinding,omitempty"`
}

func TestAttestedRotationHTTPReturnsVaultTextAndProof(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, executor := newHTTPAttestationService(t, manager, true, 1)
	input := httpSyntheticVaultText(t, "synthetic input", "synthetic source password", "source")
	output := httpSyntheticVaultText(t, "synthetic output", "synthetic destination password", "destination")
	executor.decryptedValue = "synthetic plaintext"
	executor.value = output
	binding := &attestation.Binding{Repository: "synthetic/repository", Revision: strings.Repeat("a", 40), Path: "synthetic/path"}

	body := `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":` + mustJSON(t, input) + `,"attestation":{"binding":` + mustJSON(t, binding) + `}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	result := decodeJSONBody[rotationResponseWithAttestation](t, response)
	if result.VaultText != output || result.Attestation == nil {
		t.Fatalf("rotation result = %#v", result)
	}
	if len(executor.calls) != 2 {
		t.Fatalf("executor calls = %d, want 2", len(executor.calls))
	}
}

func TestAttestationVerifyHTTPReturnsSemanticResult(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, executor := newHTTPAttestationService(t, manager, true, 1)
	input := httpSyntheticVaultText(t, "synthetic input", "synthetic source password", "source")
	output := httpSyntheticVaultText(t, "synthetic output", "synthetic destination password", "destination")
	executor.decryptedValue = "synthetic plaintext"
	executor.value = output
	binding := &attestation.Binding{Repository: "synthetic/repository", Revision: strings.Repeat("a", 40), Path: "synthetic/path"}

	rotateBody := `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":` + mustJSON(t, input) + `,"attestation":{"binding":` + mustJSON(t, binding) + `}}`
	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", strings.NewReader(rotateBody))
	rotateRequest.Header.Set("Content-Type", "application/json")
	rotateResponse := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(rotateResponse, rotateRequest)
	if rotateResponse.Code != http.StatusOK {
		t.Fatalf("rotation status = %d: %s", rotateResponse.Code, rotateResponse.Body.String())
	}
	rotation := decodeJSONBody[rotationResponseWithAttestation](t, rotateResponse)
	if rotation.Attestation == nil {
		t.Fatal("rotation response did not contain an attestation")
	}

	verifyBody, err := json.Marshal(httpVerifyRequest{
		Attestation:     *rotation.Attestation,
		InputVaultText:  input,
		OutputVaultText: output,
		ExpectedBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", strings.NewReader(string(verifyBody)))
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	verified := decodeJSONBody[verifyAttestationResponse](t, verifyResponse)
	if !verified.Valid || verified.Attestation == nil || verified.Reason != "" {
		t.Fatalf("verified response = %#v", verified)
	}

	changedOutput := httpSyntheticVaultText(t, "changed output", "synthetic destination password", "destination")
	verifyBody, err = json.Marshal(httpVerifyRequest{
		Attestation:     *rotation.Attestation,
		InputVaultText:  input,
		OutputVaultText: changedOutput,
		ExpectedBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	badRequest := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", strings.NewReader(string(verifyBody)))
	badRequest.Header.Set("Content-Type", "application/json")
	badResponse := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusOK {
		t.Fatalf("semantic failure status = %d: %s", badResponse.Code, badResponse.Body.String())
	}
	invalid := decodeJSONBody[verifyAttestationResponse](t, badResponse)
	if invalid.Valid || invalid.Reason != "output_digest_mismatch" {
		t.Fatalf("semantic failure response = %#v", invalid)
	}
}

func TestMetricsRecordAttestationAndOperationOutcomes(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, executor := newHTTPAttestationService(t, manager, true, 1)
	handler := attestationHTTPHandler(t, service)
	input := httpSyntheticVaultText(t, "synthetic input", "synthetic source password", "source")
	output := httpSyntheticVaultText(t, "synthetic output", "synthetic destination password", "destination")
	executor.decryptedValue = "synthetic plaintext"
	executor.value = output
	binding := &attestation.Binding{Repository: "synthetic/repository", Revision: strings.Repeat("a", 40), Path: "synthetic/path"}

	rotateBody := `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":` + mustJSON(t, input) + `,"attestation":{"binding":` + mustJSON(t, binding) + `}}`
	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", strings.NewReader(rotateBody))
	rotateRequest.Header.Set("Content-Type", "application/json")
	rotateResponse := httptest.NewRecorder()
	handler.ServeHTTP(rotateResponse, rotateRequest)
	if rotateResponse.Code != http.StatusOK {
		t.Fatalf("rotation status = %d: %s", rotateResponse.Code, rotateResponse.Body.String())
	}
	rotation := decodeJSONBody[rotationResponseWithAttestation](t, rotateResponse)
	if rotation.Attestation == nil {
		t.Fatal("rotation response did not contain an attestation")
	}

	verifyBody, err := json.Marshal(httpVerifyRequest{
		Attestation:     *rotation.Attestation,
		InputVaultText:  input,
		OutputVaultText: output,
		ExpectedBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", strings.NewReader(string(verifyBody)))
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", verifyResponse.Code, verifyResponse.Body.String())
	}

	metricsResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("metrics status = %d: %s", metricsResponse.Code, metricsResponse.Body.String())
	}
	body := metricsResponse.Body.String()
	for _, line := range []string{
		"vaultsmith_operation_requests_total{operation=\"rotate\",outcome=\"success\"} 1\n",
		"vaultsmith_operation_requests_total{operation=\"verify\",outcome=\"success\"} 1\n",
		"vaultsmith_attestation_issued_total{outcome=\"success\"} 1\n",
		"vaultsmith_attestation_verify_total{outcome=\"success\"} 1\n",
		"vaultsmith_attestation_keyring_loaded 1\n",
	} {
		if !strings.Contains(body, line) {
			t.Fatalf("metrics body = %q, want line %q", body, line)
		}
	}
}

func TestDisabledAttestationRequestStopsBeforeExecutor(t *testing.T) {
	service, executor := newHTTPAttestationService(t, nil, false, 1)
	body := `{"sourceProfileId":"missing","destinationProfileId":"also-missing","vaultText":"not-read-by-vault","attestation":{"binding":{"path":"synthetic"}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"feature_unavailable"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %d, want 0", len(executor.calls))
	}
}

func TestDisabledMetadataAndVerification(t *testing.T) {
	service, _ := newHTTPAttestationService(t, nil, false, 1)
	handler := attestationHTTPHandler(t, service)
	for _, path := range []string{"/.well-known/vaultsmith-attestation", "/.well-known/vaultsmith-attestation/jwks.json"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d, want 503: %s", path, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"code":"feature_unavailable"`) {
			t.Fatalf("%s body = %s", path, response.Body.String())
		}
	}
	reader := &trackingReader{}
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", reader)
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusServiceUnavailable || !strings.Contains(verifyResponse.Body.String(), `"code":"feature_unavailable"`) {
		t.Fatalf("disabled verify response: status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	if reader.read {
		t.Fatal("disabled verification body was read")
	}
}

func TestVerifierSaturationHappensBeforeBodyRead(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, _ := newHTTPAttestationService(t, manager, true, 1)
	lease, err := service.VerifierAdmission().TryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	reader := &trackingReader{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", reader)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("status = %d, Retry-After = %q, body = %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	if reader.read {
		t.Fatal("verification body was read while verifier capacity was saturated")
	}
}

func TestAttestationMetadataAndSessionCapability(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, _ := newHTTPAttestationService(t, manager, true, 1)
	handler := attestationHTTPHandler(t, service)

	metadataRequest := httptest.NewRequest(http.MethodGet, "/.well-known/vaultsmith-attestation", nil)
	metadataResponse := httptest.NewRecorder()
	handler.ServeHTTP(metadataResponse, metadataRequest)
	if metadataResponse.Code != http.StatusOK || metadataResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("metadata response: status=%d cache=%q body=%s", metadataResponse.Code, metadataResponse.Header().Get("Cache-Control"), metadataResponse.Body.String())
	}
	if metadataResponse.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("metadata content type = %q", metadataResponse.Header().Get("Content-Type"))
	}

	jwksRequest := httptest.NewRequest(http.MethodGet, "/.well-known/vaultsmith-attestation/jwks.json", nil)
	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, jwksRequest)
	if jwksResponse.Code != http.StatusOK || jwksResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("jwks response: status=%d cache=%q body=%s", jwksResponse.Code, jwksResponse.Header().Get("Cache-Control"), jwksResponse.Body.String())
	}

	sessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	sessionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sessionRecorder, sessionRequest)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("session status = %d: %s", sessionRecorder.Code, sessionRecorder.Body.String())
	}
	capability := decodeJSONBody[sessionResponse](t, sessionRecorder)
	if !capability.AttestationEnabled {
		t.Fatalf("session capability = %#v", capability)
	}

	manager.ready = false
	disabledMetadataResponse := httptest.NewRecorder()
	handler.ServeHTTP(disabledMetadataResponse, metadataRequest)
	if disabledMetadataResponse.Code != http.StatusServiceUnavailable || !strings.Contains(disabledMetadataResponse.Body.String(), `"code":"attestation_unavailable"`) {
		t.Fatalf("not-ready metadata response: status = %d body = %s", disabledMetadataResponse.Code, disabledMetadataResponse.Body.String())
	}
	unavailableSessionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unavailableSessionRecorder, sessionRequest)
	if unavailableSessionRecorder.Code != http.StatusOK {
		t.Fatalf("unavailable session status = %d: %s", unavailableSessionRecorder.Code, unavailableSessionRecorder.Body.String())
	}
	capability = decodeJSONBody[sessionResponse](t, unavailableSessionRecorder)
	if capability.AttestationEnabled {
		t.Fatalf("unavailable session capability = %#v", capability)
	}
}

func TestMalformedAttestationVerificationIsBadRequest(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, _ := newHTTPAttestationService(t, manager, true, 1)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/attestations/verify", strings.NewReader(`{"attestation":{"protected":"x","payload":"x","signature":"x"},"inputVaultText":"x","outputVaultText":"y","unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAttestationSigningFailureDoesNotReturnOutput(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	manager.signErr = errors.New("synthetic signing failure")
	service, executor := newHTTPAttestationService(t, manager, true, 1)
	input := httpSyntheticVaultText(t, "synthetic input", "synthetic source password", "source")
	output := httpSyntheticVaultText(t, "synthetic output", "synthetic destination password", "destination")
	executor.decryptedValue = "synthetic plaintext"
	executor.value = output
	body := `{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":` + mustJSON(t, input) + `,"attestation":{"binding":{"path":"synthetic"}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	attestationHTTPHandler(t, service).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), output) {
		t.Fatalf("signing failure response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAttestationBodyReadContextCancellationReturnsTemporarilyUnavailable(t *testing.T) {
	manager := newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service, _ := newHTTPAttestationService(t, manager, true, 1)
	handler := attestationHTTPHandler(t, service)

	for _, path := range []string{"/api/v1/rotations", "/api/v1/attestations/verify"} {
		t.Run(path, func(t *testing.T) {
			body := newContextBlockingBody()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := httptest.NewRequest(http.MethodPost, path, body).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				handler.ServeHTTP(response, request)
				close(done)
			}()

			select {
			case <-body.started:
			case <-time.After(time.Second):
				t.Fatal("handler did not start reading the request body")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler did not finish after request cancellation")
			}
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"code":"temporarily_unavailable"`) {
				t.Fatalf("body = %s", response.Body.String())
			}
		})
	}
}

func TestAttestedRotationRejectsInvalidUTF8BeforeService(t *testing.T) {
	executor := &fakeExecutor{value: "synthetic-output", decryptedValue: "synthetic-plaintext"}
	handler := newHandler([]Profile{{ID: "source", Label: "Source"}, {ID: "destination", Label: "Destination"}}, executor)
	raw := append([]byte(`{"sourceProfileId":"source","destinationProfileId":"destination","vaultText":"`), 0xff)
	raw = append(raw, []byte(`"}`)...)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rotations", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("response: status=%d body=%s", response.Code, response.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %d, want 0", len(executor.calls))
	}
}

type contextBlockingBody struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newContextBlockingBody() *contextBlockingBody {
	return &contextBlockingBody{started: make(chan struct{}), closed: make(chan struct{})}
}

func (b *contextBlockingBody) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *contextBlockingBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
