package vaultservice

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

type syntheticAttestationManager struct {
	issuer       string
	kid          string
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	ready        bool
	signErr      error
	signCalls    int
	resolveCalls int
	onResolve    func()
}

func newSyntheticAttestationManager(issuer string) *syntheticAttestationManager {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(publicKey, privateKey[ed25519.SeedSize:])
	return &syntheticAttestationManager{
		issuer:     issuer,
		kid:        "synthetic-key",
		privateKey: privateKey,
		publicKey:  publicKey,
		ready:      true,
	}
}

func (m *syntheticAttestationManager) Ready() bool {
	return m != nil && m.ready
}

func (m *syntheticAttestationManager) Issuer() string {
	if m == nil {
		return ""
	}
	return m.issuer
}

func (m *syntheticAttestationManager) Sign(claims attestation.RotationClaims) (attestation.Signed, error) {
	m.signCalls++
	if m.signErr != nil {
		return attestation.Signed{}, m.signErr
	}
	return attestation.Sign(claims, m.kid, m.privateKey)
}

func (m *syntheticAttestationManager) Resolve(issuer, kid string) (attestation.KeyResolution, error) {
	m.resolveCalls++
	if m.onResolve != nil {
		m.onResolve()
	}
	if issuer != m.issuer || kid != m.kid {
		return attestation.KeyResolution{}, errors.New("synthetic key lookup failed")
	}
	publicKey := make(ed25519.PublicKey, len(m.publicKey))
	copy(publicKey, m.publicKey)
	return attestation.KeyResolution{PublicKey: publicKey}, nil
}

func syntheticVaultText(t *testing.T, plaintext, password, vaultID string) string {
	t.Helper()
	value, err := ansiblevault.Encrypt([]byte(plaintext), []byte(password), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func syntheticBinding() *attestation.Binding {
	return &attestation.Binding{
		Repository: "synthetic/repository",
		Revision:   strings.Repeat("a", 40),
		Path:       "synthetic/path",
		Selector:   "synthetic_selector",
	}
}

func attestedRotationCommand(input string, binding *attestation.Binding) Command {
	return Command{
		Operation:            OperationRotate,
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Value:                input,
		Attestation:          &AttestationRequest{Binding: binding},
	}
}

func TestAttestationReadinessPreservesAvailabilityErrors(t *testing.T) {
	notReady := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	notReady.ready = false
	emptyIssuer := newSyntheticAttestationManager("")
	valid := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")

	tests := []struct {
		name    string
		service *Service
		manager AttestationManager
		code    Code
	}{
		{name: "nil service", code: CodeFeatureUnavailable},
		{
			name:    "disabled feature",
			service: &Service{attestation: valid},
			code:    CodeFeatureUnavailable,
		},
		{
			name:    "nil manager",
			service: &Service{attestationEnabled: true},
			code:    CodeAttestationUnavailable,
		},
		{
			name:    "not ready manager",
			service: &Service{attestationEnabled: true, attestation: notReady},
			code:    CodeAttestationUnavailable,
		},
		{
			name:    "empty issuer",
			service: &Service{attestationEnabled: true, attestation: emptyIssuer},
			code:    CodeAttestationUnavailable,
		},
		{
			name:    "ready manager",
			service: &Service{attestationEnabled: true, attestation: valid},
			manager: valid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := test.service.readyAttestationManager()
			if test.code != "" {
				if manager != nil || !HasCode(err, test.code) {
					t.Fatalf("readyAttestationManager() = %v, %v; want nil, %s", manager, err, test.code)
				}
				return
			}
			if err != nil || manager != test.manager {
				t.Fatalf("readyAttestationManager() = %v, %v; want %v, nil", manager, err, test.manager)
			}
		})
	}
}

func TestAttestationCallersPreservePrecedenceBeforeReadiness(t *testing.T) {
	t.Run("prepare rejects unsupported operation before availability", func(t *testing.T) {
		admission := testAdmission(t)
		service := NewWithOptions(testProfiles(), &fakeExecutor{}, nil, admission, ServiceOptions{
			AttestationEnabled: true,
		})
		lease := acquireLease(t, admission)
		command := Command{
			Operation: OperationEncrypt,
			ProfileID: "dev",
			Value:     "synthetic",
			Attestation: &AttestationRequest{
				Binding: syntheticBinding(),
			},
		}
		_, err := service.Prepare(lease.Context(context.Background()), caller.Anonymous(), command, lease)
		if !HasCode(err, CodeInvalidRequest) || HasCode(err, CodeAttestationUnavailable) {
			t.Fatalf("Prepare() error = %v, want invalid_request before readiness", err)
		}
	})

	t.Run("bearer scope is checked before availability", func(t *testing.T) {
		service := &Service{}
		err := service.PreflightAttestationVerify(context.Background(), bearerCaller(t))
		if !HasCode(err, CodeForbidden) || HasCode(err, CodeFeatureUnavailable) {
			t.Fatalf("PreflightAttestationVerify() error = %v, want forbidden before readiness", err)
		}
	})
}

func TestAttestedRotationIssuesCanonicalProofAndLegacyRunRemainsString(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	output := syntheticVaultText(t, "synthetic output", "synthetic destination password", "prod")
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	executor := &fakeExecutor{
		decrypt: func(context.Context, string, string) (string, error) {
			return "synthetic plaintext", nil
		},
		encrypt: func(context.Context, string, string) (string, error) {
			return output, nil
		},
	}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{
		AttestationManager: manager,
		AttestationEnabled: true,
	})
	lease := acquireLease(t, admission)
	bound := lease.Context(context.Background())
	prepared, err := service.Prepare(bound, caller.Anonymous(), attestedRotationCommand(input, syntheticBinding()), lease)
	if err != nil {
		t.Fatal(err)
	}

	result, err := prepared.RunResult(bound)
	if err != nil {
		t.Fatal(err)
	}
	if result.VaultText != output || result.Attestation == nil {
		t.Fatalf("rotation result did not contain the synthetic output and proof")
	}
	if manager.signCalls != 1 {
		t.Fatalf("sign calls = %d, want 1", manager.signCalls)
	}

	claims, err := service.VerifyAttestation(bound, *result.Attestation, input, output, syntheticBinding())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != manager.issuer || claims.Operation != "rotate" ||
		claims.SourceProfileID != "dev" || claims.DestinationProfileID != "prod" {
		t.Fatalf("issued claims did not preserve the rotation identity")
	}
	inputDigest, err := attestation.InputDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest, err := attestation.OutputDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Input.Value != inputDigest || claims.Output.Value != outputDigest {
		t.Fatalf("issued claims did not use canonical input/output digests")
	}

	legacyAdmission := testAdmission(t)
	legacyService := New(testProfiles(), &fakeExecutor{
		decrypt: func(context.Context, string, string) (string, error) {
			return "synthetic plaintext", nil
		},
		encrypt: func(context.Context, string, string) (string, error) {
			return output, nil
		},
	}, nil, legacyAdmission)
	legacyLease := acquireLease(t, legacyAdmission)
	legacyContext := legacyLease.Context(context.Background())
	legacyPrepared, err := legacyService.Prepare(legacyContext, caller.Anonymous(), Command{
		Operation:            OperationRotate,
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Value:                input,
	}, legacyLease)
	if err != nil {
		t.Fatal(err)
	}
	legacyOutput, err := legacyPrepared.Run(legacyContext)
	if err != nil || legacyOutput != output {
		t.Fatalf("legacy Run() = %q, %v", legacyOutput, err)
	}
}

type attestationProfileResolver struct{ configured config.Executor }

func (r attestationProfileResolver) ForProfile(id string) (ProfileExecutor, error) {
	return r.configured.ForProfile(id)
}

type realAttestationFixture struct {
	service *Service
	input   string
	result  RotationResult
	binding *attestation.Binding
}

func newRealAttestationFixture(t testing.TB) realAttestationFixture {
	t.Helper()
	configured, err := config.LoadJSON(`[{"id":"dev","label":"Synthetic source","passwordEnv":"TEST_SOURCE_PASSWORD"},{"id":"prod","label":"Synthetic destination","passwordEnv":"TEST_DESTINATION_PASSWORD"}]`, func(name string) (string, bool) {
		switch name {
		case "TEST_SOURCE_PASSWORD":
			return "synthetic source password", true
		case "TEST_DESTINATION_PASSWORD":
			return "synthetic destination password", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatal("load synthetic profiles failed")
	}
	source, err := configured.Executor().ForProfile("dev")
	if err != nil {
		t.Fatal("resolve synthetic source failed")
	}
	plaintext := strings.Repeat("s", MaxPlaintextBytes)
	input, err := source.Encrypt(t.Context(), plaintext)
	if err != nil {
		t.Fatal("encrypt synthetic maximum plaintext failed")
	}
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	service := NewWithOptions(testProfiles(), attestationProfileResolver{configured.Executor()}, nil, nil, ServiceOptions{
		AttestationManager: manager,
		AttestationEnabled: true,
	})
	lease, err := service.Admission().TryAcquire(t.Context())
	if err != nil {
		t.Fatal("acquire synthetic rotation lease failed")
	}
	defer lease.Release()
	bound := lease.Context(t.Context())
	binding := syntheticBinding()
	prepared, err := service.Prepare(bound, caller.Anonymous(), attestedRotationCommand(input, binding), lease)
	if err != nil {
		t.Fatal("prepare real synthetic rotation failed")
	}
	result, err := prepared.RunResult(bound)
	if err != nil || result.Attestation == nil {
		t.Fatal("real synthetic rotation did not issue an attestation")
	}
	destination, err := configured.Executor().ForProfile("prod")
	if err != nil {
		t.Fatal("resolve synthetic destination failed")
	}
	decrypted, err := destination.Decrypt(t.Context(), result.VaultText)
	if err != nil || decrypted != plaintext {
		t.Fatal("real rotation did not preserve the maximum synthetic plaintext")
	}
	return realAttestationFixture{service: service, input: input, result: result, binding: binding}
}

func TestAttestedRotationRealExecutorRoundTrip(t *testing.T) {
	fixture := newRealAttestationFixture(t)
	claims, err := fixture.service.VerifyAttestation(t.Context(), *fixture.result.Attestation, fixture.input, fixture.result.VaultText, fixture.binding)
	if err != nil || claims.Operation != "rotate" || claims.SourceProfileID != "dev" || claims.DestinationProfileID != "prod" {
		t.Fatal("genuinely service-issued proof did not verify for the real rotation")
	}
	t.Logf("plaintext_bytes=%d input_envelope_bytes=%d output_envelope_bytes=%d destination_decrypt_matches=true issued_proof_verified=true", MaxPlaintextBytes, len(fixture.input), len(fixture.result.VaultText))
}

func TestAttestedRotationBindingCanonicalSize(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	output := syntheticVaultText(t, "synthetic output", "synthetic destination password", "prod")
	// The four JSON member names and punctuation add 55 bytes to these values.
	boundary := attestation.Binding{
		Repository: strings.Repeat("&", 1024),
		Revision:   strings.Repeat("r", 1024),
		Path:       strings.Repeat("p", 1024),
		Selector:   strings.Repeat("s", 969),
	}
	overBoundary := boundary
	overBoundary.Selector += "s"
	tests := []struct {
		name    string
		binding attestation.Binding
		invalid bool
	}{
		{name: "ampersands", binding: attestation.Binding{Selector: strings.Repeat("&", 700)}},
		{name: "less than", binding: attestation.Binding{Repository: strings.Repeat("<", 700)}},
		{name: "greater than", binding: attestation.Binding{Path: strings.Repeat(">", 700)}},
		{name: "line separator", binding: attestation.Binding{Revision: strings.Repeat("\u2028", 341)}},
		{name: "paragraph separator", binding: attestation.Binding{Revision: strings.Repeat("\u2029", 341)}},
		{name: "exact canonical limit", binding: boundary},
		{name: "over canonical limit", binding: overBoundary, invalid: true},
		{name: "empty", invalid: true},
		{name: "oversized field", binding: attestation.Binding{Selector: strings.Repeat("s", 1025)}, invalid: true},
		{name: "oversized UTF-8 field", binding: attestation.Binding{Path: strings.Repeat("é", 513)}, invalid: true},
		{name: "control character", binding: attestation.Binding{Repository: "synthetic\nrepository"}, invalid: true},
		{name: "invalid UTF-8", binding: attestation.Binding{Revision: string([]byte{0xff})}, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
			executor := &fakeExecutor{
				decrypt: func(context.Context, string, string) (string, error) { return "synthetic plaintext", nil },
				encrypt: func(context.Context, string, string) (string, error) { return output, nil },
			}
			service := NewWithOptions(testProfiles(), executor, nil, testAdmission(t), ServiceOptions{
				AttestationEnabled: true,
				AttestationManager: manager,
			})
			lease := acquireLease(t, service.Admission())
			bound := lease.Context(t.Context())
			result, err := service.RotateResult(bound, caller.Anonymous(), "dev", "prod", input,
				&AttestationRequest{Binding: &test.binding})
			if test.invalid {
				if !HasCode(err, CodeInvalidRequest) || result.VaultText != "" || result.Attestation != nil {
					t.Fatalf("invalid binding returned output/proof or wrong error: %v", err)
				}
				if len(executor.calls) != 0 || manager.signCalls != 0 {
					t.Fatal("invalid binding performed Vault work or signed a proof")
				}
				return
			}
			if err != nil || result.VaultText != output || result.Attestation == nil {
				t.Fatalf("valid binding did not return rotated output and proof: %v", err)
			}
			if len(executor.calls) != 2 || manager.signCalls != 1 {
				t.Fatal("valid binding did not complete one attested rotation")
			}
			claims, err := service.VerifyAttestation(bound, *result.Attestation, input, output, &test.binding)
			if err != nil || claims.Binding == nil || *claims.Binding != test.binding {
				t.Fatalf("proof did not verify with the original binding and envelopes: %v", err)
			}
		})
	}
}

func TestDelegatedRotationPreservesProofBindingAndDenial(t *testing.T) {
	policy, _ := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, rotation:dev:prod, rotate, allow\np, role:operator, profile:dev, decrypt, deny\np, role:operator, profile:prod, encrypt, deny\n")
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	output := syntheticVaultText(t, "synthetic output", "synthetic destination password", "prod")
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	executor := &fakeExecutor{encrypt: func(context.Context, string, string) (string, error) { return output, nil }}
	service := NewWithOptions(testProfiles(), executor, policy, testAdmission(t), ServiceOptions{AttestationEnabled: true, AttestationManager: manager})
	lease := acquireLease(t, service.Admission())
	bound := lease.Context(context.Background())
	result, err := service.RotateResult(bound, bearerCaller(t, ScopeRotate), "dev", "prod", input, &AttestationRequest{Binding: syntheticBinding()})
	if err != nil || result.Attestation == nil || result.VaultText != output || manager.signCalls != 1 || len(executor.calls) != 2 {
		t.Fatalf("delegated RotateResult() did not return the expected proof/output; error = %v", err)
	}
	claims, err := service.VerifyAttestation(bound, *result.Attestation, input, output, syntheticBinding())
	if err != nil || claims.SourceProfileID != "dev" || claims.DestinationProfileID != "prod" {
		t.Fatalf("delegated proof verification failed or lost its pair binding; error = %v", err)
	}
	executor.calls = nil
	result, err = service.RotateResult(bound, bearerCaller(t, ScopeRotate), "prod", "dev", input, &AttestationRequest{Binding: syntheticBinding()})
	if !IsPolicyDenied(err) || result.VaultText != "" || result.Attestation != nil || manager.signCalls != 1 || len(executor.calls) != 0 {
		t.Fatalf("denied delegated rotation returned output, proof, or work; error = %v", err)
	}
}

func TestLegacyRunRejectsAttestationBeforeVaultWork(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	executor := &fakeExecutor{
		decrypt: func(context.Context, string, string) (string, error) {
			return "synthetic plaintext", nil
		},
		encrypt: func(context.Context, string, string) (string, error) {
			return "synthetic output", nil
		},
	}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{
		AttestationManager: newSyntheticAttestationManager("https://vaultsmith.synthetic.test"),
		AttestationEnabled: true,
	})
	lease := acquireLease(t, admission)
	bound := lease.Context(context.Background())
	prepared, err := service.Prepare(bound, caller.Anonymous(), attestedRotationCommand(input, syntheticBinding()), lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Run(bound); !HasCode(err, CodeInvalidRequest) {
		t.Fatalf("legacy Run() error = %v, want invalid_request", err)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("legacy Run() executed Vault work: %#v", executor.calls)
	}
}

func TestDisabledAttestationFailsBeforeProfileResolutionOrVaultWork(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	executor := &fakeExecutor{}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{
		AttestationEnabled: false,
	})
	executor.resolved = nil
	lease := acquireLease(t, admission)
	_, err := service.Prepare(lease.Context(context.Background()), caller.Anonymous(), attestedRotationCommand(input, syntheticBinding()), lease)
	if !HasCode(err, CodeFeatureUnavailable) {
		t.Fatalf("disabled attestation error = %v, want feature_unavailable", err)
	}
	if len(executor.resolved) != 0 || len(executor.calls) != 0 {
		t.Fatalf("disabled attestation performed profile or Vault work")
	}
}

func TestAttestationSigningFailureReturnsNoRotationOutput(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	output := syntheticVaultText(t, "synthetic output", "synthetic destination password", "prod")
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	manager.signErr = errors.New("synthetic signing failure")
	executor := &fakeExecutor{
		decrypt: func(context.Context, string, string) (string, error) {
			return "synthetic plaintext", nil
		},
		encrypt: func(context.Context, string, string) (string, error) {
			return output, nil
		},
	}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{
		AttestationManager: manager,
		AttestationEnabled: true,
	})
	lease := acquireLease(t, admission)
	bound := lease.Context(context.Background())
	prepared, err := service.Prepare(bound, caller.Anonymous(), attestedRotationCommand(input, syntheticBinding()), lease)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prepared.RunResult(bound)
	if result.VaultText != "" || result.Attestation != nil || !HasCode(err, CodeAttestationUnavailable) {
		t.Fatalf("signing failure leaked a successful rotation result: result=%#v err=%v", result, err)
	}
}

func TestVerifyAttestationUsesKeyringOnlyAndVerifierAdmissionIsBounded(t *testing.T) {
	input := syntheticVaultText(t, "synthetic input", "synthetic source password", "dev")
	output := syntheticVaultText(t, "synthetic output", "synthetic destination password", "prod")
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	issuer := manager.issuer
	inputDigest, err := attestation.InputDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest, err := attestation.OutputDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := manager.Sign(attestation.RotationClaims{
		Version:              attestation.SupportedVersion,
		Issuer:               issuer,
		IssuedAt:             "2026-08-15T00:00:00Z",
		Operation:            "rotate",
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Input:                attestation.Digest{Algorithm: "sha-256", Value: inputDigest},
		Output:               attestation.Digest{Algorithm: "sha-256", Value: outputDigest},
		Binding:              syntheticBinding(),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifierAdmission, err := NewVerifierAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	service := NewWithOptions(testProfiles(), &fakeExecutor{}, nil, testAdmission(t), ServiceOptions{
		AttestationManager: manager,
		AttestationEnabled: true,
		VerifierAdmission:  verifierAdmission,
	})
	if service.VerifierAdmission() != verifierAdmission || verifierAdmission.Capacity() != 1 {
		t.Fatalf("service did not expose its verifier admission")
	}
	lease := acquireVerifierLease(t, verifierAdmission)
	if _, err := service.VerifyAttestation(context.Background(), signed, input, output, syntheticBinding()); !errors.Is(err, ErrVerifierAdmissionSaturated) {
		t.Fatalf("saturated verifier error = %v, want ErrVerifierAdmissionSaturated", err)
	}
	lease.Release()

	if _, err := service.VerifyAttestation(context.Background(), signed, input, output, syntheticBinding()); err != nil {
		t.Fatal(err)
	}
	if manager.resolveCalls == 0 {
		t.Fatal("verification did not use the issuer-bound key resolver")
	}

	for _, test := range []struct {
		name     string
		provided bool
		detached bool
		before   bool
		pool     string
	}{
		{name: "internal cancellation during verification"},
		{name: "provided cancellation during verification", provided: true},
		{name: "detached origin cancellation during verification", provided: true, detached: true},
		{name: "detached origin cancelled before verification", provided: true, detached: true, before: true},
		{name: "detached operation origin cancellation during verification", provided: true, detached: true, pool: "operation"},
		{name: "detached foreign verifier origin cancellation during verification", provided: true, detached: true, pool: "foreign verifier"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var provided *VerifierLease
			providedAdmission := verifierAdmission
			switch test.pool {
			case "operation":
				providedAdmission, err = NewAdmission(1)
			case "foreign verifier":
				providedAdmission, err = NewVerifierAdmission(1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.provided {
				provided, err = providedAdmission.TryAcquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer provided.Release()
				ctx = provided.Context(ctx)
			}
			if test.detached {
				ctx = context.WithoutCancel(ctx)
			}
			if test.before {
				cancel()
			}
			manager.onResolve = cancel
			defer func() { manager.onResolve = nil }()
			claims, verifyErr := service.VerifyAttestation(ctx, signed, input, output, syntheticBinding())
			if claims != (attestation.RotationClaims{}) || !HasCode(verifyErr, CodeTemporarilyUnavailable) || !errors.Is(verifyErr, context.Canceled) {
				t.Error("cancelled verification must return empty claims and temporarily_unavailable wrapping context.Canceled")
			}
			if provided != nil {
				if providedAdmission.InUse() != 1 {
					t.Error("verification released the caller-owned lease")
				}
				provided.Release()
			}
			if verifierAdmission.InUse() != 0 || providedAdmission.InUse() != 0 {
				t.Error("verification did not restore admission capacity after owner release")
			}
			manager.onResolve = nil
			if _, err := service.VerifyAttestation(context.Background(), signed, input, output, syntheticBinding()); err != nil {
				t.Fatalf("non-cancelled verification after release failed: %v", err)
			}
		})
	}
}

func acquireVerifierLease(t *testing.T, admission *VerifierAdmission) *VerifierLease {
	t.Helper()
	lease, err := admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	return lease
}
