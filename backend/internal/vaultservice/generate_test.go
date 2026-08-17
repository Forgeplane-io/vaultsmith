package vaultservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/generate"
)

type recordingMaterialGenerator struct {
	delegate    MaterialGenerator
	calls       []GenerateKind
	failureKind GenerateKind
	failure     error
	lastPrivate []byte
	lastResult  any
}

func newRecordingMaterialGenerator() *recordingMaterialGenerator {
	return &recordingMaterialGenerator{delegate: generate.New()}
}

func (g *recordingMaterialGenerator) fail(kind GenerateKind) error {
	g.calls = append(g.calls, kind)
	if g.failureKind == kind && g.failure != nil {
		return g.failure
	}
	return nil
}

func (g *recordingMaterialGenerator) record(result any, private []byte) {
	g.lastResult = result
	g.lastPrivate = append(g.lastPrivate[:0], private...)
	clear(private)
}

func (g *recordingMaterialGenerator) GeneratePassword(parameters generate.PasswordParameters) (generate.PasswordResult, error) {
	if err := g.fail(GenerateKindPassword); err != nil {
		return generate.PasswordResult{}, err
	}
	result, err := g.delegate.GeneratePassword(parameters)
	if err == nil {
		g.record(result, result.PrivateBytes())
	}
	return result, err
}

func (g *recordingMaterialGenerator) GenerateToken(parameters generate.TokenParameters) (generate.TokenResult, error) {
	if err := g.fail(GenerateKindToken); err != nil {
		return generate.TokenResult{}, err
	}
	result, err := g.delegate.GenerateToken(parameters)
	if err == nil {
		g.record(result, result.PrivateBytes())
	}
	return result, err
}

func (g *recordingMaterialGenerator) GenerateSSHKeyPair(parameters generate.SSHKeyPairParameters) (generate.SSHKeyPairResult, error) {
	if err := g.fail(GenerateKindSSHKeyPair); err != nil {
		return generate.SSHKeyPairResult{}, err
	}
	result, err := g.delegate.GenerateSSHKeyPair(parameters)
	if err == nil {
		g.record(result, result.PrivateBytes())
	}
	return result, err
}

func (g *recordingMaterialGenerator) GenerateAgeIdentity() (generate.AgeIdentityResult, error) {
	if err := g.fail(GenerateKindAgeIdentity); err != nil {
		return generate.AgeIdentityResult{}, err
	}
	result, err := g.delegate.GenerateAgeIdentity()
	if err == nil {
		g.record(result, result.PrivateBytes())
	}
	return result, err
}

func (g *recordingMaterialGenerator) GenerateX509CSR(parameters generate.X509CSRParameters) (generate.X509CSRResult, error) {
	if err := g.fail(GenerateKindX509CSR); err != nil {
		return generate.X509CSRResult{}, err
	}
	result, err := g.delegate.GenerateX509CSR(parameters)
	if err == nil {
		g.record(result, result.PrivateBytes())
	}
	return result, err
}

func TestGenerateAuthorizesBeforeVariantAndGeneratorValidation(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	policy := &fakeAuthorizer{decisions: map[string]error{
		authz.ActionEncrypt + "\x00" + authz.ProfileResource("dev"): authz.ErrForbidden,
	}}
	executor := &fakeExecutor{}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, policy, admission, ServiceOptions{Generator: generator})
	lease := acquireLease(t, admission)

	// The selected pointer is intentionally wrong and the selected SSH
	// algorithm would also be invalid. Neither fact may be inspected by the
	// generator before the destination policy denies access.
	command := GenerateCommand{
		ProfileID: "dev",
		Kind:      GenerateKindSSHKeyPair,
		Password:  &generate.PasswordParameters{},
	}
	_, err := service.Generate(lease.Context(context.Background()), bearerCaller(t, ScopeEncrypt), command)
	if !IsPolicyDenied(err) || !HasCode(err, CodeForbidden) {
		t.Fatalf("Generate() error = %v, want policy-denied forbidden", err)
	}
	if len(generator.calls) != 0 {
		t.Fatalf("generator calls = %#v, want none", generator.calls)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
	wantAuthorization := []authorizationCall{{
		kind:     caller.KindBearer,
		action:   authz.ActionEncrypt,
		resource: authz.ProfileResource("dev"),
	}}
	if !reflect.DeepEqual(policy.calls, wantAuthorization) {
		t.Fatalf("authorization calls = %#v, want %#v", policy.calls, wantAuthorization)
	}
}

func TestGenerateSealsExactPrivateBytesAndMapsEveryResultKind(t *testing.T) {
	vaultPassword := []byte("test-only-vault-password")
	hexEncoding := generate.TokenEncodingHex
	tokenBytes := 16

	tests := []struct {
		name    string
		command GenerateCommand
		check   func(*testing.T, GenerateResult, any)
	}{
		{
			name: "password",
			command: GenerateCommand{
				ProfileID: "dev",
				Kind:      GenerateKindPassword,
				Password:  &generate.PasswordParameters{},
			},
			check: func(t *testing.T, result GenerateResult, generatorResult any) {
				t.Helper()
				got, ok := result.(GeneratedPasswordResult)
				if !ok {
					t.Fatalf("result type = %T", result)
				}
				generated := generatorResult.(generate.PasswordResult)
				if got.EffectiveParameters != generated.EffectiveParameters() || got.Secret.Format != generate.PasswordFormat {
					t.Fatalf("password result = %#v", got)
				}
			},
		},
		{
			name: "token",
			command: GenerateCommand{
				ProfileID: "dev",
				Kind:      GenerateKindToken,
				Token: &generate.TokenParameters{
					Encoding: &hexEncoding,
					Bytes:    &tokenBytes,
				},
			},
			check: func(t *testing.T, result GenerateResult, generatorResult any) {
				t.Helper()
				got, ok := result.(GeneratedTokenResult)
				if !ok {
					t.Fatalf("result type = %T", result)
				}
				generated := generatorResult.(generate.TokenResult)
				if got.EffectiveParameters != generated.EffectiveParameters() || got.Secret.Format != generate.TokenHexFormat {
					t.Fatalf("token result = %#v", got)
				}
			},
		},
		{
			name: "ssh keypair",
			command: GenerateCommand{
				ProfileID:  "dev",
				Kind:       GenerateKindSSHKeyPair,
				SSHKeyPair: &generate.SSHKeyPairParameters{Algorithm: generate.SSHAlgorithmEd25519},
			},
			check: func(t *testing.T, result GenerateResult, generatorResult any) {
				t.Helper()
				got, ok := result.(GeneratedSSHKeyPairResult)
				if !ok {
					t.Fatalf("result type = %T", result)
				}
				generated := generatorResult.(generate.SSHKeyPairResult)
				if got.Algorithm != generated.Algorithm() || got.Secret.Format != generate.SSHPrivateFormat ||
					got.Public != (GeneratedSSHPublic{Format: generate.SSHPublicFormat, AuthorizedKey: generated.AuthorizedKey(), Fingerprint: generated.Fingerprint()}) {
					t.Fatalf("SSH result = %#v", got)
				}
			},
		},
		{
			name: "age identity",
			command: GenerateCommand{
				ProfileID:   "dev",
				Kind:        GenerateKindAgeIdentity,
				AgeIdentity: &AgeIdentityParameters{},
			},
			check: func(t *testing.T, result GenerateResult, generatorResult any) {
				t.Helper()
				got, ok := result.(GeneratedAgeIdentityResult)
				if !ok {
					t.Fatalf("result type = %T", result)
				}
				generated := generatorResult.(generate.AgeIdentityResult)
				if got.Algorithm != "x25519" || got.Secret.Format != generate.AgePrivateFormat ||
					got.Public != (GeneratedAgePublic{Format: generate.AgePublicFormat, Recipient: generated.Recipient()}) {
					t.Fatalf("age result = %#v", got)
				}
			},
		},
		{
			name: "X.509 CSR",
			command: GenerateCommand{
				ProfileID: "dev",
				Kind:      GenerateKindX509CSR,
				X509CSR: &generate.X509CSRParameters{
					Algorithm: generate.X509AlgorithmEd25519,
					SANs:      &generate.X509SANs{DNSNames: []string{"service.example.test"}},
				},
			},
			check: func(t *testing.T, result GenerateResult, generatorResult any) {
				t.Helper()
				got, ok := result.(GeneratedX509CSRResult)
				if !ok {
					t.Fatalf("result type = %T", result)
				}
				generated := generatorResult.(generate.X509CSRResult)
				if got.Algorithm != generated.Algorithm() || got.Secret.Format != generate.X509PrivateFormat ||
					got.Public != (GeneratedX509Public{Format: generate.X509PublicFormat, CSRPEM: generated.CSRPEM(), Fingerprint: generated.Fingerprint()}) {
					t.Fatalf("X.509 result = %#v", got)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			var encryptedBytes []byte
			executor := &fakeExecutor{encrypt: func(_ context.Context, profileID, value string) (string, error) {
				encryptedBytes = append([]byte(nil), []byte(value)...)
				return ansiblevault.Encrypt([]byte(value), vaultPassword, profileID)
			}}
			policy := &fakeAuthorizer{decisions: map[string]error{}}
			admission := testAdmission(t)
			service := NewWithOptions(testProfiles(), executor, policy, admission, ServiceOptions{Generator: generator})
			lease := acquireLease(t, admission)

			result, err := service.Generate(lease.Context(context.Background()), sessionCaller(t), test.command)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			if !reflect.DeepEqual(encryptedBytes, generator.lastPrivate) {
				t.Fatal("profile executor did not receive the exact generated private serialization")
			}
			secret := result.SealedSecret()
			decrypted, err := ansiblevault.Decrypt(secret.VaultText, vaultPassword)
			if err != nil {
				t.Fatalf("decrypt generated Vault text: %v", err)
			}
			if !reflect.DeepEqual(decrypted, generator.lastPrivate) {
				t.Fatal("Vault text does not contain the exact generated private serialization")
			}
			if result.MaterialKind() != test.command.Kind || result.DestinationProfileID() != test.command.ProfileID {
				t.Fatalf("result identity = %q/%q", result.MaterialKind(), result.DestinationProfileID())
			}
			if !strings.HasPrefix(secret.VaultText, ansiblevault.Header12Prefix+";dev\n") {
				t.Fatalf("Vault header = %q", strings.SplitN(secret.VaultText, "\n", 2)[0])
			}
			if len(generator.calls) != 1 || generator.calls[0] != test.command.Kind {
				t.Fatalf("generator calls = %#v", generator.calls)
			}
			if len(policy.calls) != 1 || policy.calls[0].action != authz.ActionEncrypt {
				t.Fatalf("authorization calls = %#v", policy.calls)
			}
			test.check(t, result, generator.lastResult)
		})
	}
}

func TestGenerateRejectsNonCanonicalOrMislabeledVaultOutput(t *testing.T) {
	canonical, err := ansiblevault.Encrypt([]byte("synthetic"), []byte("password"), "dev")
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := ansiblevault.Encrypt([]byte("synthetic"), []byte("password"), "prod")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		output string
	}{
		{name: "wrong profile label", output: wrongProfile},
		{name: "Vault 1.1 header", output: strings.Replace(canonical, ansiblevault.Header12Prefix+";dev", ansiblevault.Header11, 1)},
		{name: "non-canonical line endings", output: strings.ReplaceAll(canonical, "\n", "\r\n")},
		{name: "malformed envelope", output: "$ANSIBLE_VAULT;1.2;AES256;dev\nnot-vault-data\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			executor := &fakeExecutor{encrypt: func(context.Context, string, string) (string, error) {
				return test.output, nil
			}}
			admission := testAdmission(t)
			service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{Generator: generator})
			lease := acquireLease(t, admission)
			result, err := service.Generate(lease.Context(context.Background()), caller.Anonymous(), GenerateCommand{
				ProfileID: "dev",
				Kind:      GenerateKindToken,
				Token:     &generate.TokenParameters{},
			})
			if result != nil || !HasCode(err, CodeOperationFailed) {
				t.Fatalf("Generate() = %#v, %v, want nil operation_failed", result, err)
			}
		})
	}
}

func TestGenerateCollapsesGeneratorAndVaultFailures(t *testing.T) {
	tests := []struct {
		name          string
		generatorErr  error
		executorErr   error
		wantCode      Code
		wantGenerator bool
		wantExecutor  bool
	}{
		{
			name:          "invalid generator parameters",
			generatorErr:  generate.ErrInvalidParameters,
			wantCode:      CodeInvalidRequest,
			wantGenerator: true,
		},
		{
			name:          "generator dependency",
			generatorErr:  errors.New("private generator diagnostic"),
			wantCode:      CodeOperationFailed,
			wantGenerator: true,
		},
		{
			name:          "profile encryption",
			executorErr:   errors.New("private profile diagnostic"),
			wantCode:      CodeOperationFailed,
			wantGenerator: true,
			wantExecutor:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := newRecordingMaterialGenerator()
			generator.failureKind = GenerateKindToken
			generator.failure = test.generatorErr
			executor := &fakeExecutor{encrypt: func(_ context.Context, profileID, value string) (string, error) {
				if test.executorErr != nil {
					return "", test.executorErr
				}
				return ansiblevault.Encrypt([]byte(value), []byte("password"), profileID)
			}}
			admission := testAdmission(t)
			service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{Generator: generator})
			lease := acquireLease(t, admission)
			result, err := service.Generate(lease.Context(context.Background()), caller.Anonymous(), GenerateCommand{
				ProfileID: "dev",
				Kind:      GenerateKindToken,
				Token:     &generate.TokenParameters{},
			})
			if result != nil || !HasCode(err, test.wantCode) {
				t.Fatalf("Generate() = %#v, %v, want nil %q", result, err, test.wantCode)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("Generate() exposed dependency error: %q", err)
			}
			if got := len(generator.calls) > 0; got != test.wantGenerator {
				t.Fatalf("generator called = %v, want %v", got, test.wantGenerator)
			}
			if got := len(executor.calls) > 0; got != test.wantExecutor {
				t.Fatalf("executor called = %v, want %v", got, test.wantExecutor)
			}
		})
	}
}

func TestGenerateValidatesCoreParametersOnlyAfterAllowedProfilePolicy(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	policy := &fakeAuthorizer{decisions: map[string]error{}}
	executor := &fakeExecutor{}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, policy, admission, ServiceOptions{Generator: generator})
	lease := acquireLease(t, admission)
	tooShort := 15

	result, err := service.Generate(lease.Context(context.Background()), sessionCaller(t), GenerateCommand{
		ProfileID: "dev",
		Kind:      GenerateKindToken,
		Token:     &generate.TokenParameters{Bytes: &tooShort},
	})
	if result != nil || !HasCode(err, CodeInvalidRequest) {
		t.Fatalf("Generate() = %#v, %v, want nil invalid_request", result, err)
	}
	if len(policy.calls) != 1 || policy.calls[0] != (authorizationCall{
		kind:     caller.KindSession,
		action:   authz.ActionEncrypt,
		resource: authz.ProfileResource("dev"),
	}) {
		t.Fatalf("authorization calls = %#v, want one encrypt decision", policy.calls)
	}
	if want := []GenerateKind{GenerateKindToken}; !reflect.DeepEqual(generator.calls, want) {
		t.Fatalf("generator calls = %#v, want %#v", generator.calls, want)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
}

type blockingTokenGenerator struct {
	MaterialGenerator
	started chan struct{}
	release chan struct{}
}

func (g *blockingTokenGenerator) GenerateToken(parameters generate.TokenParameters) (generate.TokenResult, error) {
	close(g.started)
	<-g.release
	return g.MaterialGenerator.GenerateToken(parameters)
}

func TestGenerateCancellationAfterSynchronousGenerationSkipsEncryption(t *testing.T) {
	blocking := &blockingTokenGenerator{
		MaterialGenerator: generate.New(),
		started:           make(chan struct{}),
		release:           make(chan struct{}),
	}
	executor := &fakeExecutor{}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{Generator: blocking})

	origin, cancel := context.WithCancel(context.Background())
	lease, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	bound := lease.Context(origin)
	outcome := make(chan error, 1)
	go func() {
		_, generateErr := service.Generate(bound, caller.Anonymous(), GenerateCommand{
			ProfileID: "dev",
			Kind:      GenerateKindToken,
			Token:     &generate.TokenParameters{},
		})
		outcome <- generateErr
	}()

	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("generator did not start")
	}
	cancel()
	close(blocking.release)
	select {
	case err := <-outcome:
		if !HasCode(err, CodeTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Generate() error = %v, want safe cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Generate did not return after generator boundary")
	}
	lease.Release()
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
}

func TestGenerateCancellationDuringProfileEncryptionFailsClosed(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	encryptionStarted := make(chan struct{})
	executor := &fakeExecutor{encrypt: func(ctx context.Context, _, _ string) (string, error) {
		close(encryptionStarted)
		<-ctx.Done()
		return "", ctx.Err()
	}}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), executor, nil, admission, ServiceOptions{Generator: generator})

	origin, cancel := context.WithCancel(context.Background())
	lease, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	bound := lease.Context(origin)
	outcome := make(chan struct {
		result GenerateResult
		err    error
	}, 1)
	go func() {
		result, generateErr := service.Generate(bound, caller.Anonymous(), GenerateCommand{
			ProfileID: "dev",
			Kind:      GenerateKindToken,
			Token:     &generate.TokenParameters{},
		})
		outcome <- struct {
			result GenerateResult
			err    error
		}{result: result, err: generateErr}
	}()

	select {
	case <-encryptionStarted:
	case <-time.After(time.Second):
		t.Fatal("profile encryption did not start")
	}
	cancel()
	select {
	case got := <-outcome:
		if got.result != nil || !HasCode(got.err, CodeTemporarilyUnavailable) || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Generate() = %#v, %v, want nil safe cancellation", got.result, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Generate did not return after encryption cancellation")
	}
	lease.Release()
	if len(generator.calls) != 1 || len(executor.calls) != 1 {
		t.Fatalf("generator/executor calls = %#v/%#v, want one each", generator.calls, executor.calls)
	}
}

func TestGenerateUsesExistingUnknownProfileVisibility(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	policy := &fakeAuthorizer{decisions: map[string]error{}}
	admission := testAdmission(t)
	service := NewWithOptions(testProfiles(), &fakeExecutor{}, policy, admission, ServiceOptions{Generator: generator})
	command := GenerateCommand{ProfileID: "missing", Kind: GenerateKindToken, Token: &generate.TokenParameters{}}

	for _, test := range []struct {
		name  string
		actor caller.Caller
		code  Code
	}{
		{name: "anonymous", actor: caller.Anonymous(), code: CodeNotFound},
		{name: "authenticated", actor: sessionCaller(t), code: CodeForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := acquireLease(t, admission)
			result, err := service.Generate(lease.Context(context.Background()), test.actor, command)
			lease.Release()
			if result != nil || !HasCode(err, test.code) {
				t.Fatalf("Generate() = %#v, %v, want nil %q", result, err, test.code)
			}
		})
	}
	if len(generator.calls) != 0 {
		t.Fatalf("generator calls = %#v, want none", generator.calls)
	}
}

func TestGenerateRequiresBoundAdmissionLeaseAndEncryptScope(t *testing.T) {
	generator := newRecordingMaterialGenerator()
	service := NewWithOptions(testProfiles(), &fakeExecutor{}, &fakeAuthorizer{}, testAdmission(t), ServiceOptions{Generator: generator})
	command := GenerateCommand{ProfileID: "dev", Kind: GenerateKindToken, Token: &generate.TokenParameters{}}

	if _, err := service.Generate(context.Background(), caller.Anonymous(), command); !HasCode(err, CodeNotReady) {
		t.Fatalf("Generate(without lease) error = %v, want not_ready", err)
	}
	invalidWithoutLease := GenerateCommand{ProfileID: "INVALID", Kind: GenerateKind("unknown")}
	if _, err := service.Generate(context.Background(), caller.Anonymous(), invalidWithoutLease); !HasCode(err, CodeNotReady) {
		t.Fatalf("Generate(invalid without lease) error = %v, want lease not_ready before request validation", err)
	}
	if err := service.PreflightGenerate(context.Background(), bearerCaller(t, ScopeDecrypt)); !HasCode(err, CodeForbidden) {
		t.Fatalf("PreflightGenerate(decrypt scope) error = %v, want forbidden", err)
	}
	if err := service.PreflightGenerate(context.Background(), bearerCaller(t, ScopeEncrypt)); err != nil {
		t.Fatalf("PreflightGenerate(encrypt scope) error = %v", err)
	}
	if len(generator.calls) != 0 {
		t.Fatalf("generator calls = %#v, want none", generator.calls)
	}
}
