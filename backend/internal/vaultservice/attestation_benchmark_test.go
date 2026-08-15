package vaultservice

import (
	"context"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
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

func BenchmarkRotateAttestationOverhead(b *testing.B) {
	input, err := ansiblevault.Encrypt([]byte("synthetic rotation input"), []byte("synthetic source password"), "dev")
	if err != nil {
		b.Fatal(err)
	}
	output, err := ansiblevault.Encrypt([]byte("synthetic rotation output"), []byte("synthetic destination password"), "prod")
	if err != nil {
		b.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		attested bool
	}{
		{name: "without-attestation"},
		{name: "with-attestation", attested: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			executor := &fakeExecutor{
				decrypt: func(context.Context, string, string) (string, error) {
					return "synthetic rotation plaintext", nil
				},
				encrypt: func(context.Context, string, string) (string, error) {
					return output, nil
				},
			}
			admission, err := NewAdmission(1)
			if err != nil {
				b.Fatal(err)
			}
			manager := newSyntheticAttestationManager("https://vaultsmith.synthetic.test")
			service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{
				AttestationManager: manager,
				AttestationEnabled: true,
			})
			binding := syntheticBinding()
			var request *AttestationRequest
			if test.attested {
				request = &AttestationRequest{Binding: binding}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lease, err := admission.TryAcquire(context.Background())
				if err != nil {
					b.Fatal(err)
				}
				bound := lease.Context(context.Background())
				prepared, err := service.Prepare(bound, caller.Anonymous(), Command{
					Operation:            OperationRotate,
					SourceProfileID:      "dev",
					DestinationProfileID: "prod",
					Value:                input,
					Attestation:          request,
				}, lease)
				if err != nil {
					lease.Release()
					b.Fatal(err)
				}
				result, err := prepared.RunResult(bound)
				lease.Release()
				if err != nil {
					b.Fatal(err)
				}
				if result.VaultText != output || (test.attested && result.Attestation == nil) || (!test.attested && result.Attestation != nil) {
					b.Fatalf("unexpected rotation result: attested=%t result=%#v", test.attested, result)
				}
			}
		})
	}
}
