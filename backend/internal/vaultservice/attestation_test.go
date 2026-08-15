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
