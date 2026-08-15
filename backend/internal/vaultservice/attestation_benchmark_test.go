package vaultservice

import (
	"context"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
)

func BenchmarkIssueAttestation(b *testing.B) {
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	claims := attestation.RotationClaims{
		Version:              attestation.SupportedVersion,
		Issuer:               manager.issuer,
		IssuedAt:             "2026-08-15T00:00:00Z",
		Operation:            "rotate",
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Input:                attestation.Digest{Algorithm: "sha-256", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Output:               attestation.Digest{Algorithm: "sha-256", Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Binding:              syntheticBinding(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := manager.Sign(claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAttestation(b *testing.B) {
	input, err := ansiblevault.Encrypt([]byte("synthetic input"), []byte("synthetic source password"), "dev")
	if err != nil {
		b.Fatal(err)
	}
	output, err := ansiblevault.Encrypt([]byte("synthetic output"), []byte("synthetic destination password"), "prod")
	if err != nil {
		b.Fatal(err)
	}
	inputDigest, err := attestation.InputDigest(input)
	if err != nil {
		b.Fatal(err)
	}
	outputDigest, err := attestation.OutputDigest(output)
	if err != nil {
		b.Fatal(err)
	}
	manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
	binding := syntheticBinding()
	signed, err := manager.Sign(attestation.RotationClaims{
		Version:              attestation.SupportedVersion,
		Issuer:               manager.issuer,
		IssuedAt:             "2026-08-15T00:00:00Z",
		Operation:            "rotate",
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Input:                attestation.Digest{Algorithm: "sha-256", Value: inputDigest},
		Output:               attestation.Digest{Algorithm: "sha-256", Value: outputDigest},
		Binding:              binding,
	})
	if err != nil {
		b.Fatal(err)
	}
	admission, err := NewAdmission(2)
	if err != nil {
		b.Fatal(err)
	}
	verifierAdmission, err := NewVerifierAdmission(1)
	if err != nil {
		b.Fatal(err)
	}
	service := NewWithOptions(testProfiles(), &fakeExecutor{}, nil, admission, ServiceOptions{
		AttestationManager: manager,
		AttestationEnabled: true,
		VerifierAdmission:  verifierAdmission,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := service.VerifyAttestation(context.Background(), signed, input, output, binding); err != nil {
			b.Fatal(err)
		}
	}
}
