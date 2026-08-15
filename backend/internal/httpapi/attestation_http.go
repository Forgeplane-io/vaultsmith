package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

const (
	maxAttestationVerifyBodyBytes      = 12 << 20
	maxAttestationJWSComponentBytes    = 64 << 10
	maxAttestationJWSObjectBytes       = 192 << 10
	maxAttestationBindingFieldBytes    = 1 << 10
	maxAttestationCanonicalBindingSize = 4 << 10
)

type rotationAttestationRequest struct {
	Binding *attestation.Binding
}

type rotationRequestWithAttestation struct {
	SourceProfileID      string
	DestinationProfileID string
	VaultText            string
	Attestation          *rotationAttestationRequest
}

type rotationResponseWithAttestation struct {
	VaultText   string              `json:"vaultText"`
	Attestation *attestation.Signed `json:"attestation,omitempty"`
}

type verifyAttestationRequest struct {
	Attestation     attestation.Signed
	InputVaultText  string
	OutputVaultText string
	ExpectedBinding *attestation.Binding
}

type verifyAttestationResponse struct {
	Valid       bool                           `json:"valid"`
	Reason      attestation.VerificationReason `json:"reason,omitempty"`
	Attestation *verifiedAttestationClaims     `json:"attestation,omitempty"`
}

type verifiedAttestationClaims struct {
	Issuer               string               `json:"issuer"`
	IssuedAt             string               `json:"issuedAt"`
	Operation            string               `json:"operation"`
	SourceProfileID      string               `json:"sourceProfileId"`
	DestinationProfileID string               `json:"destinationProfileId"`
	KID                  string               `json:"kid"`
	Binding              *attestation.Binding `json:"binding,omitempty"`
}

func (h *Handler) serveCanonicalRotateWithAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	if err := h.preflightOperation(r.Context(), actor, vaultservice.OperationRotate); err != nil {
		if actor.Kind() == caller.KindBearer && vaultservice.HasCode(err, vaultservice.CodeForbidden) {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeRotate, protectedResourceMetadataURL(h.authConfig))
		} else {
			writeServiceError(w, err)
		}
		return
	}
	lease, err := h.service.Admission().TryAcquire(r.Context())
	if err != nil {
		if errors.Is(err, vaultservice.ErrAdmissionSaturated) {
			writeAdmissionSaturated(w, h.service.Admission())
		} else if isContextError(err) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeServiceError(w, err)
		}
		return
	}
	defer lease.Release()
	leaseContext := lease.Context(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) || isMaxBytesError(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		} else if isContextError(err) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		}
		return
	}
	if isContextError(r.Context().Err()) {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		return
	}
	request, err := parseRotationRequestWithAttestation(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	var serviceAttestation *vaultservice.AttestationRequest
	if request.Attestation != nil {
		serviceAttestation = &vaultservice.AttestationRequest{Binding: request.Attestation.Binding}
	}
	command := vaultservice.Command{
		Operation:            vaultservice.OperationRotate,
		SourceProfileID:      request.SourceProfileID,
		DestinationProfileID: request.DestinationProfileID,
		Value:                request.VaultText,
		Attestation:          serviceAttestation,
	}
	prepared, err := h.service.Prepare(leaseContext, actor, command, lease)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	result, err := prepared.RunResult(leaseContext)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotationResponseWithAttestation{VaultText: result.VaultText, Attestation: result.Attestation})
}

func parseRotationRequestWithAttestation(raw []byte) (rotationRequestWithAttestation, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return rotationRequestWithAttestation{}, errors.New("request is not valid UTF-8")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"sourceProfileId": {}, "destinationProfileId": {}, "vaultText": {}, "attestation": {},
	})
	if err != nil {
		return rotationRequestWithAttestation{}, err
	}
	var result rotationRequestWithAttestation
	for key, target := range map[string]*string{
		"sourceProfileId":      &result.SourceProfileID,
		"destinationProfileId": &result.DestinationProfileID,
		"vaultText":            &result.VaultText,
	} {
		rawValue, ok := fields[key]
		if !ok {
			return rotationRequestWithAttestation{}, errors.New("required request field is missing")
		}
		value, err := decodeOperationString(rawValue)
		if err != nil {
			return rotationRequestWithAttestation{}, err
		}
		*target = value
	}
	if rawValue, ok := fields["attestation"]; ok {
		request, err := parseRotationAttestationRequest(rawValue)
		if err != nil {
			return rotationRequestWithAttestation{}, err
		}
		result.Attestation = request
	}
	return result, nil
}

func parseRotationAttestationRequest(raw json.RawMessage) (*rotationAttestationRequest, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("attestation must be an object")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{"binding": {}})
	if err != nil {
		return nil, err
	}
	result := &rotationAttestationRequest{}
	if binding, ok := fields["binding"]; ok {
		parsed, err := parseBinding(binding)
		if err != nil {
			return nil, err
		}
		result.Binding = parsed
	}
	return result, nil
}

func (h *Handler) serveAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeAttestationUnavailable), "rotation attestation service is unavailable")
		return
	}
	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	if err := h.service.PreflightAttestationVerify(r.Context(), actor); err != nil {
		if actor.Kind() == caller.KindBearer && vaultservice.HasCode(err, vaultservice.CodeForbidden) {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeAttestationVerify, protectedResourceMetadataURL(h.authConfig))
		} else {
			writeServiceError(w, err)
		}
		return
	}
	if h.service == nil || !h.service.AttestationEnabled() {
		writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeFeatureUnavailable), "rotation attestations are disabled")
		return
	}
	admission := h.service.VerifierAdmission()
	lease, err := admission.TryAcquire(r.Context())
	if err != nil {
		if errors.Is(err, vaultservice.ErrVerifierAdmissionSaturated) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeAttestationBusy), "rotation attestation verification is busy")
		} else {
			writeError(w, http.StatusServiceUnavailable, string(vaultservice.CodeAttestationUnavailable), "rotation attestation service is unavailable")
		}
		return
	}
	leaseContext := lease.Context(r.Context())
	defer lease.Release()
	r.Body = http.MaxBytesReader(w, r.Body, maxAttestationVerifyBodyBytes)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		if isMaxBytesError(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		} else if isContextError(err) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid attestation verification request")
		}
		return
	}
	if isContextError(r.Context().Err()) {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		return
	}
	request, err := parseVerifyAttestationRequest(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid attestation verification request")
		return
	}
	claims, err := h.service.VerifyAttestation(leaseContext, request.Attestation, request.InputVaultText, request.OutputVaultText, request.ExpectedBinding)
	if reason, ok := attestation.VerificationReasonOf(err); ok {
		response := verifyAttestationResponse{Valid: false, Reason: reason}
		if claims.Issuer != "" && reason != attestation.SignatureInvalid && reason != attestation.UnknownKey && reason != attestation.IssuerMismatch {
			response.Attestation = h.safeClaimsResponse(request.Attestation, claims)
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err != nil {
		if vaultservice.HasCode(err, vaultservice.CodeInvalidRequest) || errors.Is(err, attestation.ErrMalformed) {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid attestation verification request")
		} else {
			writeServiceError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, verifyAttestationResponse{Valid: true, Attestation: h.safeClaimsResponse(request.Attestation, claims)})
}

func parseVerifyAttestationRequest(raw []byte) (verifyAttestationRequest, error) {
	if !utf8.Valid(raw) || len(raw) == 0 {
		return verifyAttestationRequest{}, errors.New("invalid request")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"attestation": {}, "inputVaultText": {}, "outputVaultText": {}, "expectedBinding": {},
	})
	if err != nil {
		return verifyAttestationRequest{}, err
	}
	attestationRaw, ok := fields["attestation"]
	if !ok {
		return verifyAttestationRequest{}, errors.New("attestation is required")
	}
	signed, err := parseSignedAttestation(attestationRaw)
	if err != nil {
		return verifyAttestationRequest{}, err
	}
	inputRaw, ok := fields["inputVaultText"]
	if !ok {
		return verifyAttestationRequest{}, errors.New("inputVaultText is required")
	}
	outputRaw, ok := fields["outputVaultText"]
	if !ok {
		return verifyAttestationRequest{}, errors.New("outputVaultText is required")
	}
	input, err := boundedString(inputRaw, vaultservice.MaxVaultTextBytes)
	if err != nil {
		return verifyAttestationRequest{}, err
	}
	output, err := boundedString(outputRaw, vaultservice.MaxVaultTextBytes)
	if err != nil {
		return verifyAttestationRequest{}, err
	}
	result := verifyAttestationRequest{Attestation: signed, InputVaultText: input, OutputVaultText: output}
	if bindingRaw, ok := fields["expectedBinding"]; ok {
		result.ExpectedBinding, err = parseBinding(bindingRaw)
		if err != nil {
			return verifyAttestationRequest{}, err
		}
	}
	return result, nil
}

func parseSignedAttestation(raw json.RawMessage) (attestation.Signed, error) {
	if len(raw) > maxAttestationJWSObjectBytes || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return attestation.Signed{}, errors.New("invalid attestation")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{"protected": {}, "payload": {}, "signature": {}})
	if err != nil {
		return attestation.Signed{}, err
	}
	var signed attestation.Signed
	for name, target := range map[string]*string{
		"protected": &signed.Protected,
		"payload":   &signed.Payload,
		"signature": &signed.Signature,
	} {
		value, ok := fields[name]
		if !ok {
			return attestation.Signed{}, errors.New("attestation member is missing")
		}
		decoded, err := decodeOperationString(value)
		if err != nil || len(decoded) > maxAttestationJWSComponentBytes {
			return attestation.Signed{}, errors.New("attestation member is invalid")
		}
		*target = decoded
	}
	if _, err := attestation.Parse(raw); err != nil {
		return attestation.Signed{}, err
	}
	return signed, nil
}

func parseBinding(raw json.RawMessage) (*attestation.Binding, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("binding must be an object")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"repository": {}, "revision": {}, "path": {}, "selector": {},
	})
	if err != nil {
		return nil, err
	}
	result := &attestation.Binding{}
	for name, target := range map[string]*string{
		"repository": &result.Repository,
		"revision":   &result.Revision,
		"path":       &result.Path,
		"selector":   &result.Selector,
	} {
		value, ok := fields[name]
		if !ok {
			continue
		}
		decoded, err := decodeOperationString(value)
		if err != nil || len(decoded) > maxAttestationBindingFieldBytes || !utf8.ValidString(decoded) {
			return nil, errors.New("binding is invalid")
		}
		*target = decoded
	}
	if result.Repository == "" && result.Revision == "" && result.Path == "" && result.Selector == "" {
		return nil, errors.New("binding must not be empty")
	}
	if len(result.Repository)+len(result.Revision)+len(result.Path)+len(result.Selector) > maxAttestationCanonicalBindingSize {
		return nil, errors.New("binding is too large")
	}
	return result, nil
}

func boundedString(raw json.RawMessage, limit int) (string, error) {
	value, err := decodeOperationString(raw)
	if err != nil || !utf8.ValidString(value) || len(value) > limit {
		return "", errors.New("value is invalid")
	}
	return value, nil
}

func (h *Handler) safeClaimsResponse(signed attestation.Signed, claims attestation.RotationClaims) *verifiedAttestationClaims {
	kid := ""
	if protected, err := base64.RawURLEncoding.DecodeString(signed.Protected); err == nil {
		if fields, err := decodeStrictObject(protected, map[string]struct{}{"alg": {}, "kid": {}, "typ": {}}); err == nil {
			if value, err := decodeOperationString(fields["kid"]); err == nil {
				kid = value
			}
		}
	}
	return &verifiedAttestationClaims{
		Issuer: claims.Issuer, IssuedAt: claims.IssuedAt, Operation: claims.Operation,
		SourceProfileID: claims.SourceProfileID, DestinationProfileID: claims.DestinationProfileID,
		KID: kid, Binding: claims.Binding,
	}
}

func (h *Handler) serveAttestationMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.service == nil {
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
		return
	}
	raw, err := h.service.MetadataJSON()
	if err != nil {
		if vaultservice.HasCode(err, vaultservice.CodeFeatureUnavailable) {
			writeError(w, http.StatusNotFound, "not_found", "resource was not found")
			return
		}
		writeServiceError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, raw)
}

func (h *Handler) serveAttestationJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.service == nil {
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
		return
	}
	raw, err := h.service.JWKSJSON()
	if err != nil {
		if vaultservice.HasCode(err, vaultservice.CodeFeatureUnavailable) {
			writeError(w, http.StatusNotFound, "not_found", "resource was not found")
			return
		}
		writeServiceError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, raw)
}

func writeRawJSON(w http.ResponseWriter, status int, raw []byte) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	ensureRequestID(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.Copy(w, bytes.NewReader(raw))
	_, _ = io.WriteString(w, "\n")
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isMaxBytesError(err error) bool {
	var target *http.MaxBytesError
	return errors.As(err, &target)
}
