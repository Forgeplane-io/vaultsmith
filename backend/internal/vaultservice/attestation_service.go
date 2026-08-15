package vaultservice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

const ScopeAttestationVerify = "vaultsmith.attestation.verify"

// RotationResult is the result-aware form of a rotation. Legacy callers can
// continue using PreparedOperation.Run, while proof-aware callers use
// RunResult or RunWithResult.
type RotationResult struct {
	VaultText   string              `json:"vaultText"`
	Attestation *attestation.Signed `json:"attestation,omitempty"`
}

// AttestationRequest opts a rotate command into local proof issuance.
type AttestationRequest struct {
	Binding *attestation.Binding `json:"binding,omitempty"`
}

// RotationAttestationRequest is a descriptive alias for callers that want to
// name the request by operation rather than transport feature.
type RotationAttestationRequest = AttestationRequest

// AttestationManager is the service-layer seam for the local keyring manager.
// It intentionally contains only signing and issuer-bound resolution; the
// concrete manager remains outside this package to avoid an import cycle.
type AttestationManager interface {
	Ready() bool
	Issuer() string
	Sign(attestation.RotationClaims) (attestation.Signed, error)
	Resolve(string, string) (attestation.KeyResolution, error)
}

// AttestationDiscovery is implemented by the concrete manager for its
// deterministic public discovery documents. It is optional on the signing
// seam so synthetic service tests do not need to construct discovery fixtures.
type AttestationDiscovery interface {
	MetadataJSON() ([]byte, error)
	JWKSJSON() ([]byte, error)
}

// ServiceOptions adds dependency injection seams without changing New's
// existing signature or behavior.
type ServiceOptions struct {
	AttestationManager AttestationManager
	// Attestation is a compatibility spelling for AttestationManager.
	Attestation        AttestationManager
	AttestationEnabled bool
	// ProofsEnabled is a compatibility spelling for AttestationEnabled.
	ProofsEnabled     bool
	VerifierAdmission *VerifierAdmission
}

// Options is a short alias for ServiceOptions.
type Options = ServiceOptions

// NewWithOptions constructs the service with optional proof dependencies.
// Proofs remain disabled unless explicitly enabled, preserving New behavior.
func NewWithOptions(profiles []Profile, executor Executor, authorizer Authorizer, admission *Admission, options ServiceOptions) *Service {
	if admission == nil {
		admission = NewRuntimeAdmission()
	}
	verifierAdmission := options.VerifierAdmission
	if verifierAdmission == nil {
		verifierAdmission = NewRuntimeVerifierAdmission()
	}
	manager := options.AttestationManager
	if manager == nil {
		manager = options.Attestation
	}
	entries := make([]catalogEntry, 0, len(profiles))
	byID := make(map[string]catalogEntry, len(profiles))
	ready := len(profiles) > 0 && executor != nil && admission != nil
	for _, input := range profiles {
		profile := Profile{ID: input.ID, Label: input.Label}
		if !config.IsValidProfileID(profile.ID) || strings.TrimSpace(profile.Label) == "" {
			ready = false
		}
		if _, duplicate := byID[profile.ID]; duplicate {
			ready = false
		}
		var bound ProfileExecutor
		if executor != nil {
			resolved, err := executor.ForProfile(profile.ID)
			if err == nil {
				bound = resolved
			}
		}
		if bound == nil {
			ready = false
		}
		entry := catalogEntry{profile: profile, executor: bound}
		entries = append(entries, entry)
		byID[profile.ID] = entry
	}
	return &Service{
		profiles:           entries,
		byID:               byID,
		authorizer:         authorizer,
		admission:          admission,
		ready:              ready,
		attestation:        manager,
		attestationEnabled: options.AttestationEnabled || options.ProofsEnabled,
		verifierAdmission:  verifierAdmission,
	}
}

// VerifierAdmission exposes the separate nonblocking verification pool so a
// transport can reserve capacity before reading a proof request body.
func (s *Service) VerifierAdmission() *Admission {
	if s == nil {
		return nil
	}
	return s.verifierAdmission
}

// AttestationEnabled reports whether proofs are enabled and a valid immutable
// keyring snapshot is available. Unavailable or not-ready managers must not
// advertise the capability to session callers.
func (s *Service) AttestationEnabled() bool {
	return s != nil && s.attestationEnabled && s.attestation != nil && s.attestation.Ready()
}

func cloneAttestationRequest(request *AttestationRequest) *AttestationRequest {
	if request == nil {
		return nil
	}
	clone := &AttestationRequest{}
	if request.Binding != nil {
		binding := *request.Binding
		clone.Binding = &binding
	}
	return clone
}

func validateAttestationRequest(request *AttestationRequest) error {
	if request == nil || request.Binding == nil {
		return nil
	}
	binding := request.Binding
	fields := []string{binding.Repository, binding.Revision, binding.Path, binding.Selector}
	hasValue := false
	for _, field := range fields {
		if field == "" {
			continue
		}
		hasValue = true
		if len(field) > 1<<10 || !utf8.ValidString(field) {
			return invalidRequest("attestation binding is invalid")
		}
		for _, r := range field {
			if unicode.IsControl(r) {
				return invalidRequest("attestation binding is invalid")
			}
		}
	}
	if !hasValue {
		return invalidRequest("attestation binding is invalid")
	}
	canonical, err := json.Marshal(binding)
	if err != nil || len(canonical) > 4<<10 {
		return invalidRequest("attestation binding is invalid")
	}
	return nil
}

func (s *Service) attestationRequestAvailable() error {
	if s == nil || !s.attestationEnabled {
		return featureUnavailable()
	}
	if s.attestation == nil || !s.attestation.Ready() || s.attestation.Issuer() == "" {
		return attestationUnavailable()
	}
	return nil
}

func (s *Service) discoveryReady() error {
	if s == nil || !s.attestationEnabled {
		return featureUnavailable()
	}
	if s.attestation == nil {
		return attestationUnavailable()
	}
	if !s.attestation.Ready() {
		return attestationUnavailable()
	}
	if s.attestation.Issuer() == "" {
		return attestationUnavailable()
	}
	return nil
}

func (s *Service) verificationManager() (AttestationManager, error) {
	if err := s.discoveryReady(); err != nil {
		return nil, err
	}
	return s.attestation, nil
}

// PreflightAttestationVerify performs availability and caller checks without
// reading, parsing, or retaining any proof body.
func (s *Service) PreflightAttestationVerify(ctx context.Context, actor caller.Caller) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	switch actor.Kind() {
	case caller.KindAnonymous, caller.KindSession:
		// Availability is checked below after caller classification.
	case caller.KindBearer:
		if !actor.HasScope(ScopeAttestationVerify) {
			return forbidden()
		}
	default:
		return notReady("caller is not ready")
	}
	return s.discoveryReady()
}

// MetadataJSON returns the manager's deterministic public metadata document.
// It performs no profile lookup or Vault work.
func (s *Service) MetadataJSON() ([]byte, error) {
	if err := s.discoveryReady(); err != nil {
		return nil, err
	}
	discovery, ok := s.attestation.(AttestationDiscovery)
	if !ok {
		return nil, attestationUnavailable()
	}
	data, err := discovery.MetadataJSON()
	if err != nil {
		return nil, attestationUnavailable()
	}
	return append([]byte(nil), data...), nil
}

// JWKSJSON returns the manager's deterministic public JWKS document. Private
// key material and Vault data never cross this service boundary.
func (s *Service) JWKSJSON() ([]byte, error) {
	if err := s.discoveryReady(); err != nil {
		return nil, err
	}
	discovery, ok := s.attestation.(AttestationDiscovery)
	if !ok {
		return nil, attestationUnavailable()
	}
	data, err := discovery.JWKSJSON()
	if err != nil {
		return nil, attestationUnavailable()
	}
	return append([]byte(nil), data...), nil
}

// VerifyAttestation verifies a supplied flattened JWS against the local
// issuer, current keyring resolver, canonical input/output envelopes, and the
// expected binding. It never resolves a profile or performs Vault work.
func (s *Service) VerifyAttestation(ctx context.Context, signed attestation.Signed, inputEnvelope, outputEnvelope string, expectedBinding *attestation.Binding) (attestation.RotationClaims, error) {
	manager, err := s.verificationManager()
	if err != nil {
		return attestation.RotationClaims{}, err
	}
	if err := contextError(ctx); err != nil {
		return attestation.RotationClaims{}, err
	}
	if !utf8.ValidString(inputEnvelope) || !utf8.ValidString(outputEnvelope) || inputEnvelope == "" || outputEnvelope == "" || len(inputEnvelope) > MaxVaultTextBytes || len(outputEnvelope) > MaxVaultTextBytes {
		return attestation.RotationClaims{}, attestation.ErrMalformed
	}

	var release func()
	provided := leaseFromContext(ctx)
	if provided != nil && provided.liveForContext(ctx, s.verifierAdmission) {
		if !provided.holdForContext(ctx, s.verifierAdmission) {
			return attestation.RotationClaims{}, attestationBusy()
		}
		release = provided.releaseHold
	} else {
		if s.verifierAdmission == nil {
			return attestation.RotationClaims{}, attestationUnavailable()
		}
		lease, acquireErr := s.verifierAdmission.TryAcquire(ctx)
		if acquireErr != nil {
			if errors.Is(acquireErr, ErrVerifierAdmissionSaturated) || errors.Is(acquireErr, ErrAdmissionSaturated) {
				return attestation.RotationClaims{}, attestationBusy()
			}
			if errors.Is(acquireErr, context.Canceled) || errors.Is(acquireErr, context.DeadlineExceeded) {
				return attestation.RotationClaims{}, temporarilyUnavailable(acquireErr)
			}
			return attestation.RotationClaims{}, attestationUnavailable()
		}
		release = lease.Release
	}
	defer release()
	if err := contextError(ctx); err != nil {
		return attestation.RotationClaims{}, err
	}

	if !manager.Ready() {
		return attestation.RotationClaims{}, attestationUnavailable()
	}
	claims, verifyErr := attestation.VerifyAgainstEnvelopes(signed, inputEnvelope, outputEnvelope, expectedBinding, attestation.VerifyOptions{
		ExpectedIssuer: manager.Issuer(),
		Resolver:       manager,
	})
	if !manager.Ready() {
		return attestation.RotationClaims{}, attestationUnavailable()
	}
	if errors.Is(verifyErr, attestation.ErrMalformed) || errors.Is(verifyErr, attestation.ErrInvalidVerifyOptions) {
		return attestation.RotationClaims{}, invalidAttestationRequest(verifyErr)
	}
	return claims, verifyErr
}

func (p *PreparedOperation) issueAttestation(invocation, execution context.Context, outputEnvelope string) (attestation.Signed, error) {
	if err := leaseMergedContextError(invocation, execution, p.lease); err != nil {
		return attestation.Signed{}, err
	}
	manager, err := p.service.verificationManager()
	if err != nil {
		return attestation.Signed{}, err
	}
	inputDigest, err := attestation.InputDigest(p.value)
	if err != nil {
		return attestation.Signed{}, invalidRequest("attestation input is invalid")
	}
	outputDigest, err := attestation.OutputDigest(outputEnvelope)
	if err != nil {
		return attestation.Signed{}, invalidRequest("attestation output is invalid")
	}
	if contextErr := leaseMergedContextError(invocation, execution, p.lease); contextErr != nil {
		return attestation.Signed{}, contextErr
	}
	claims := attestation.RotationClaims{
		Version:              attestation.SupportedVersion,
		Issuer:               manager.Issuer(),
		IssuedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		Operation:            string(OperationRotate),
		SourceProfileID:      p.sourceProfileID(),
		DestinationProfileID: p.destinationProfileID(),
		Input:                attestation.Digest{Algorithm: "sha-256", Value: inputDigest},
		Output:               attestation.Digest{Algorithm: "sha-256", Value: outputDigest},
	}
	if p.attestation != nil && p.attestation.Binding != nil {
		binding := *p.attestation.Binding
		claims.Binding = &binding
	}
	signed, err := manager.Sign(claims)
	if contextErr := leaseMergedContextError(invocation, execution, p.lease); contextErr != nil {
		return attestation.Signed{}, contextErr
	}
	if err != nil {
		return attestation.Signed{}, attestationUnavailable()
	}
	wire, err := attestation.Marshal(signed)
	if err != nil {
		return attestation.Signed{}, attestationUnavailable()
	}
	if _, err := attestation.Parse(wire); err != nil {
		return attestation.Signed{}, attestationUnavailable()
	}
	return signed, nil
}

func (p *PreparedOperation) sourceProfileID() string {
	if p == nil {
		return ""
	}
	return p.sourceID
}

func (p *PreparedOperation) destinationProfileID() string {
	if p == nil {
		return ""
	}
	return p.destinationID
}
