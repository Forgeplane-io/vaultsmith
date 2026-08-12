package vaultservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
)

type authorizationCall struct {
	kind     caller.Kind
	action   string
	resource string
}

type fakeAuthorizer struct {
	decisions   map[string]error
	err         error
	calls       []authorizationCall
	evaluations int
}

type authorizerFunc func(caller.Caller, []authz.Check) ([]bool, error)

func (f authorizerFunc) Evaluate(actor caller.Caller, checks []authz.Check) ([]bool, error) {
	return f(actor, checks)
}

func (f *fakeAuthorizer) Evaluate(actor caller.Caller, checks []authz.Check) ([]bool, error) {
	f.evaluations++
	if f.err != nil {
		return nil, f.err
	}
	allowed := make([]bool, len(checks))
	for index, check := range checks {
		f.calls = append(f.calls, authorizationCall{kind: actor.Kind(), action: check.Action, resource: check.Resource})
		decision := f.decisions[check.Action+"\x00"+check.Resource]
		switch {
		case decision == nil:
			allowed[index] = true
		case errors.Is(decision, authz.ErrForbidden):
			allowed[index] = false
		default:
			return nil, decision
		}
	}
	return allowed, nil
}

type executorCall struct {
	operation string
	profileID string
	value     string
}

type failingResolver struct{}

func (failingResolver) ForProfile(string) (ProfileExecutor, error) {
	return nil, errors.New("resolver failed")
}

type fakeExecutor struct {
	encrypt  func(context.Context, string, string) (string, error)
	decrypt  func(context.Context, string, string) (string, error)
	calls    []executorCall
	resolved []string
}

type fakeProfileExecutor struct {
	owner     *fakeExecutor
	profileID string
}

func (f *fakeExecutor) ForProfile(profileID string) (ProfileExecutor, error) {
	f.resolved = append(f.resolved, profileID)
	return &fakeProfileExecutor{owner: f, profileID: profileID}, nil
}

func (f *fakeProfileExecutor) Encrypt(ctx context.Context, plaintext string) (string, error) {
	f.owner.calls = append(f.owner.calls, executorCall{operation: "encrypt", profileID: f.profileID, value: plaintext})
	if f.owner.encrypt != nil {
		return f.owner.encrypt(ctx, f.profileID, plaintext)
	}
	return "encrypted", nil
}

func (f *fakeProfileExecutor) Decrypt(ctx context.Context, vaultText string) (string, error) {
	f.owner.calls = append(f.owner.calls, executorCall{operation: "decrypt", profileID: f.profileID, value: vaultText})
	if f.owner.decrypt != nil {
		return f.owner.decrypt(ctx, f.profileID, vaultText)
	}
	return "plaintext", nil
}

func testProfiles() []Profile {
	return []Profile{{ID: "dev", Label: "Development"}, {ID: "prod", Label: "Production"}}
}

func testAdmission(t *testing.T) *Admission {
	t.Helper()
	admission, err := NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

func acquireLease(t *testing.T, admission *Admission) *Lease {
	t.Helper()
	return acquireLeaseForContext(t, admission, context.Background())
}

func acquireLeaseForContext(t *testing.T, admission *Admission, ctx context.Context) *Lease {
	t.Helper()
	lease, err := admission.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	return lease
}

func sessionCaller(t *testing.T) caller.Caller {
	t.Helper()
	actor, err := caller.NewSession("https://issuer.example", "subject", []string{"operators"})
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func bearerCaller(t *testing.T, scopes ...string) caller.Caller {
	t.Helper()
	actor, err := caller.NewBearer("https://issuer.example", "service-account", []string{"operators"}, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func TestListProfilesFailsClosedWhenServiceIsNotReady(t *testing.T) {
	tests := []struct {
		name     string
		profiles []Profile
		resolver Executor
	}{
		{name: "empty catalog", resolver: &fakeExecutor{}},
		{name: "profile resolution failed", profiles: testProfiles(), resolver: failingResolver{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := New(test.profiles, test.resolver, nil, testAdmission(t))
			if _, err := service.ListProfiles(context.Background(), caller.Anonymous()); !HasCode(err, CodeNotReady) {
				t.Fatalf("ListProfiles() error = %v, want not_ready", err)
			}
		})
	}
}

func TestListProfilesUsesCallerScopeAndPolicyIntersection(t *testing.T) {
	policy := &fakeAuthorizer{decisions: map[string]error{
		authz.ActionDecrypt + "\x00" + authz.ProfileResource("prod"): authz.ErrForbidden,
	}}
	service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))

	anonymous, err := service.ListProfiles(context.Background(), caller.Anonymous())
	if err != nil {
		t.Fatalf("anonymous ListProfiles() error = %v", err)
	}
	all := ProfileCapabilities{Encrypt: true, Decrypt: true, RotateSource: true, RotateDestination: true}
	if want := []Profile{{ID: "dev", Label: "Development", Capabilities: all}, {ID: "prod", Label: "Production", Capabilities: all}}; !reflect.DeepEqual(anonymous, want) {
		t.Fatalf("anonymous profiles = %#v, want %#v", anonymous, want)
	}
	if len(policy.calls) != 0 {
		t.Fatalf("anonymous listing called policy: %#v", policy.calls)
	}

	policy.calls = nil
	session, err := service.ListProfiles(context.Background(), sessionCaller(t))
	if err != nil {
		t.Fatalf("session ListProfiles() error = %v", err)
	}
	wantSession := []Profile{
		{ID: "dev", Label: "Development", Capabilities: all},
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{Encrypt: true, RotateDestination: true}},
	}
	if !reflect.DeepEqual(session, wantSession) {
		t.Fatalf("session profiles = %#v, want %#v", session, wantSession)
	}

	policy.calls = nil
	rotateOnly, err := service.ListProfiles(context.Background(), bearerCaller(t, ScopeProfileRead, ScopeRotate))
	if err != nil {
		t.Fatalf("bearer ListProfiles() error = %v", err)
	}
	wantBearer := []Profile{
		{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestination: true}},
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{RotateDestination: true}},
	}
	if !reflect.DeepEqual(rotateOnly, wantBearer) {
		t.Fatalf("bearer profiles = %#v, want %#v", rotateOnly, wantBearer)
	}

	if _, err := service.ListProfiles(context.Background(), bearerCaller(t, ScopeEncrypt)); !HasCode(err, CodeForbidden) {
		t.Fatalf("bearer listing without profile scope error = %v, want forbidden", err)
	}
}

func TestListProfilesPolicyDenialIsSuccessfulEmptyCatalog(t *testing.T) {
	policy := &fakeAuthorizer{decisions: map[string]error{
		authz.ActionListProfiles + "\x00" + authz.ResourceProfiles: authz.ErrForbidden,
	}}
	service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))
	profiles, err := service.ListProfiles(context.Background(), sessionCaller(t))
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("profiles = %#v, want empty", profiles)
	}
}

func TestPrepareIsSingleAuthorizationPointAndRunIsOneShot(t *testing.T) {
	policy := &fakeAuthorizer{decisions: map[string]error{}}
	executor := &fakeExecutor{encrypt: func(ctx context.Context, profileID, value string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "vault-output", nil
	}}
	admission := testAdmission(t)
	service := New(testProfiles(), executor, policy, admission)
	if want := []string{"dev", "prod"}; !reflect.DeepEqual(executor.resolved, want) {
		t.Fatalf("catalog resolution = %#v, want %#v", executor.resolved, want)
	}
	lease := acquireLease(t, admission)
	leaseContext := lease.Context(context.Background())
	actor := sessionCaller(t)
	prepared, err := service.Prepare(leaseContext, actor, Command{
		Operation: OperationEncrypt,
		ProfileID: "dev",
		Value:     "plaintext",
	}, lease)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepared.actor.Kind() != actor.Kind() || prepared.actor.Issuer() != actor.Issuer() || prepared.actor.Subject() != actor.Subject() {
		t.Fatalf("prepared caller = %q/%q/%q, want %q/%q/%q", prepared.actor.Kind(), prepared.actor.Issuer(), prepared.actor.Subject(), actor.Kind(), actor.Issuer(), actor.Subject())
	}
	if policy.evaluations != 1 || len(policy.calls) != 1 || policy.calls[0] != (authorizationCall{kind: caller.KindSession, action: authz.ActionEncrypt, resource: authz.ProfileResource("dev")}) {
		t.Fatalf("authorization evaluations/calls = %d/%#v, want one encrypt decision", policy.evaluations, policy.calls)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("Prepare() executed operation: %#v", executor.calls)
	}
	copied := *prepared

	result, err := prepared.Run(leaseContext)
	if err != nil || result != "vault-output" {
		t.Fatalf("Run() = %q, %v", result, err)
	}
	if len(policy.calls) != 1 {
		t.Fatalf("Run() repeated authorization: %#v", policy.calls)
	}
	if len(executor.calls) != 1 || executor.calls[0] != (executorCall{operation: "encrypt", profileID: "dev", value: "plaintext"}) {
		t.Fatalf("executor calls = %#v", executor.calls)
	}
	if want := []string{"dev", "prod"}; !reflect.DeepEqual(executor.resolved, want) {
		t.Fatalf("Run() repeated profile lookup: %#v", executor.resolved)
	}
	if _, err := copied.Run(leaseContext); !HasCode(err, CodeNotReady) {
		t.Fatalf("copied Run() error = %v, want not_ready", err)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("copied Run() repeated execution: %#v", executor.calls)
	}
	if _, err := prepared.Run(leaseContext); !HasCode(err, CodeNotReady) {
		t.Fatalf("second Run() error = %v, want not_ready", err)
	}
}

func TestPrepareRequiresExactLiveLease(t *testing.T) {
	own := testAdmission(t)
	foreign := testAdmission(t)
	service := New(testProfiles(), &fakeExecutor{}, nil, own)
	command := Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}

	if _, err := service.Prepare(context.Background(), caller.Anonymous(), command, nil); !HasCode(err, CodeNotReady) {
		t.Fatalf("Prepare(nil lease) error = %v, want not_ready", err)
	}
	foreignLease := acquireLease(t, foreign)
	if _, err := service.Prepare(foreignLease.Context(context.Background()), caller.Anonymous(), command, foreignLease); !HasCode(err, CodeNotReady) {
		t.Fatalf("Prepare(foreign lease) error = %v, want not_ready", err)
	}
	lease := acquireLease(t, own)
	if _, err := service.Prepare(context.Background(), caller.Anonymous(), command, lease); !HasCode(err, CodeNotReady) {
		t.Fatalf("Prepare(unbound lease) error = %v, want not_ready", err)
	}
	leaseContext := lease.Context(context.Background())
	prepared, err := service.Prepare(leaseContext, caller.Anonymous(), command, lease)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if _, err := prepared.Run(leaseContext); !HasCode(err, CodeNotReady) {
		t.Fatalf("Run(released lease) error = %v, want not_ready", err)
	}
}

func TestCopiedLeaseReleaseInvalidatesOriginal(t *testing.T) {
	admission := testAdmission(t)
	origin := context.Background()
	lease, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	copied := *lease
	copied.Release()
	replacement, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatalf("replacement acquisition: %v", err)
	}
	executor := &fakeExecutor{}
	service := New(testProfiles(), executor, nil, admission)
	prepared, prepareErr := service.Prepare(lease.Context(origin), caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
	if !HasCode(prepareErr, CodeNotReady) || prepared != nil {
		replacement.Release()
		t.Fatalf("Prepare() = %#v, %v, want nil/not_ready", prepared, prepareErr)
	}
	if len(executor.calls) != 0 {
		replacement.Release()
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
	lease.Release()
	copied.Release()
	replacement.Release()
	if admission.InUse() != 0 {
		t.Fatalf("admission in use = %d, want 0", admission.InUse())
	}

	active, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	activeCopy := *active
	done := make(chan struct{}, 2)
	go func() {
		active.Release()
		done <- struct{}{}
	}()
	go func() {
		activeCopy.Release()
		done <- struct{}{}
	}()
	for range 2 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent copied lease release blocked")
		}
	}
	active.Release()
	activeCopy.Release()
	if admission.InUse() != 0 {
		t.Fatalf("admission in use after concurrent release = %d, want 0", admission.InUse())
	}
}

func TestPrepareValidatesCommandBeforeExecution(t *testing.T) {
	admission := testAdmission(t)
	service := New(testProfiles(), &fakeExecutor{}, nil, admission)
	tests := []struct {
		name string
		cmd  Command
		code Code
	}{
		{name: "unknown operation", cmd: Command{Operation: "unknown", ProfileID: "dev"}, code: CodeInvalidRequest},
		{name: "encrypt rotate fields", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", SourceProfileID: "dev", Value: "x"}, code: CodeInvalidRequest},
		{name: "rotate missing source", cmd: Command{Operation: OperationRotate, DestinationProfileID: "prod", Value: "x"}, code: CodeInvalidRequest},
		{name: "unknown profile in off mode", cmd: Command{Operation: OperationEncrypt, ProfileID: "missing", Value: "x"}, code: CodeNotFound},
		{name: "invalid utf8", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", Value: string([]byte{0xff})}, code: CodeInvalidRequest},
		{name: "plaintext too large", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", Value: strings.Repeat("x", MaxPlaintextBytes+1)}, code: CodeTooLarge},
		{name: "vault text too large", cmd: Command{Operation: OperationDecrypt, ProfileID: "dev", Value: strings.Repeat("x", MaxVaultTextBytes+1)}, code: CodeTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease, err := admission.TryAcquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			if _, err := service.Prepare(lease.Context(context.Background()), caller.Anonymous(), test.cmd, lease); !HasCode(err, test.code) {
				t.Fatalf("Prepare() error = %v, want code %q", err, test.code)
			}
		})
	}
}

func TestPrepareAppliesByteLimitsAtMultibyteBoundaries(t *testing.T) {
	tests := []struct {
		name string
		cmd  Command
		code Code
	}{
		{name: "empty plaintext", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", Value: ""}},
		{name: "plaintext exact", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", Value: strings.Repeat("é", MaxPlaintextBytes/2)}},
		{name: "plaintext over", cmd: Command{Operation: OperationEncrypt, ProfileID: "dev", Value: strings.Repeat("é", MaxPlaintextBytes/2+1)}, code: CodeTooLarge},
		{name: "vault text exact", cmd: Command{Operation: OperationDecrypt, ProfileID: "dev", Value: strings.Repeat("é", MaxVaultTextBytes/2)}},
		{name: "vault text over", cmd: Command{Operation: OperationDecrypt, ProfileID: "dev", Value: strings.Repeat("é", MaxVaultTextBytes/2+1)}, code: CodeTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission := testAdmission(t)
			service := New(testProfiles(), &fakeExecutor{}, nil, admission)
			lease := acquireLease(t, admission)
			_, err := service.Prepare(lease.Context(context.Background()), caller.Anonymous(), test.cmd, lease)
			if test.code == "" && err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			if test.code != "" && !HasCode(err, test.code) {
				t.Fatalf("Prepare() error = %v, want code %q", err, test.code)
			}
		})
	}
}

func TestUnknownAuthenticatedProfileAndPolicyFailuresDoNotLeak(t *testing.T) {
	policy := &fakeAuthorizer{decisions: map[string]error{}}
	admission := testAdmission(t)
	service := New(testProfiles(), &fakeExecutor{}, policy, admission)
	lease := acquireLease(t, admission)
	_, err := service.Prepare(lease.Context(context.Background()), sessionCaller(t), Command{Operation: OperationDecrypt, ProfileID: "missing", Value: "secret"}, lease)
	if !HasCode(err, CodeForbidden) || strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unknown authenticated profile error = %v", err)
	}

	lease.Release()
	lease, err = admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	policy.decisions[authz.ActionDecrypt+"\x00"+authz.ProfileResource("dev")] = authz.ErrPolicy
	_, err = service.Prepare(lease.Context(context.Background()), sessionCaller(t), Command{Operation: OperationDecrypt, ProfileID: "dev", Value: "secret"}, lease)
	if !HasCode(err, CodeNotReady) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("policy failure error = %v", err)
	}
}

func TestPolicyFailureDoesNotRevealProfileExistence(t *testing.T) {
	actors := []struct {
		name  string
		actor func(*testing.T) caller.Caller
	}{
		{name: "session", actor: sessionCaller},
		{name: "bearer", actor: func(t *testing.T) caller.Caller { return bearerCaller(t, ScopeDecrypt) }},
	}
	for _, actorTest := range actors {
		for _, profileID := range []string{"dev", "missing"} {
			t.Run(actorTest.name+"/"+profileID, func(t *testing.T) {
				policy := &fakeAuthorizer{err: authz.ErrPolicy}
				admission := testAdmission(t)
				service := New(testProfiles(), &fakeExecutor{}, policy, admission)
				lease := acquireLease(t, admission)
				_, err := service.Prepare(lease.Context(context.Background()), actorTest.actor(t), Command{Operation: OperationDecrypt, ProfileID: profileID, Value: "secret"}, lease)
				if !HasCode(err, CodeNotReady) || strings.Contains(err.Error(), profileID) || strings.Contains(err.Error(), "secret") {
					t.Fatalf("Prepare(%q) error = %v, want safe not_ready", profileID, err)
				}
				if policy.evaluations != 1 {
					t.Fatalf("policy evaluations = %d, want 1", policy.evaluations)
				}
			})
		}
	}
}

func TestPolicyDenialDoesNotRevealProfileExistence(t *testing.T) {
	actors := []struct {
		name  string
		actor func(*testing.T) caller.Caller
	}{
		{name: "session", actor: sessionCaller},
		{name: "bearer", actor: func(t *testing.T) caller.Caller { return bearerCaller(t, ScopeDecrypt) }},
	}
	for _, actorTest := range actors {
		for _, profileID := range []string{"dev", "missing"} {
			t.Run(actorTest.name+"/"+profileID, func(t *testing.T) {
				resource := authz.ProfileResource(profileID)
				policy := &fakeAuthorizer{decisions: map[string]error{authz.ActionDecrypt + "\x00" + resource: authz.ErrForbidden}}
				admission := testAdmission(t)
				service := New(testProfiles(), &fakeExecutor{}, policy, admission)
				lease := acquireLease(t, admission)
				_, err := service.Prepare(lease.Context(context.Background()), actorTest.actor(t), Command{Operation: OperationDecrypt, ProfileID: profileID, Value: "secret"}, lease)
				if !HasCode(err, CodeForbidden) || strings.Contains(err.Error(), profileID) || strings.Contains(err.Error(), "secret") {
					t.Fatalf("Prepare(%q) error = %v, want safe forbidden", profileID, err)
				}
				if policy.evaluations != 1 {
					t.Fatalf("policy evaluations = %d, want 1", policy.evaluations)
				}
			})
		}
	}
}

func TestDeniedCallersDoNotReceiveValueValidationBeforeAuthorization(t *testing.T) {
	actors := []struct {
		name  string
		actor func(*testing.T) caller.Caller
	}{
		{name: "session", actor: sessionCaller},
		{name: "bearer", actor: func(t *testing.T) caller.Caller { return bearerCaller(t, ScopeDecrypt) }},
	}
	values := []struct {
		name  string
		value string
	}{
		{name: "oversized", value: strings.Repeat("x", MaxVaultTextBytes+1)},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
	}
	for _, actorTest := range actors {
		for _, profileID := range []string{"dev", "missing"} {
			for _, valueTest := range values {
				t.Run(actorTest.name+"/"+profileID+"/"+valueTest.name, func(t *testing.T) {
					resource := authz.ProfileResource(profileID)
					policy := &fakeAuthorizer{decisions: map[string]error{authz.ActionDecrypt + "\x00" + resource: authz.ErrForbidden}}
					executor := &fakeExecutor{}
					admission := testAdmission(t)
					service := New(testProfiles(), executor, policy, admission)
					lease := acquireLease(t, admission)
					_, err := service.Prepare(lease.Context(context.Background()), actorTest.actor(t), Command{Operation: OperationDecrypt, ProfileID: profileID, Value: valueTest.value}, lease)
					if !HasCode(err, CodeForbidden) || strings.Contains(err.Error(), profileID) {
						t.Fatalf("Prepare(%q, %s) error = %v, want safe forbidden", profileID, valueTest.name, err)
					}
					if policy.evaluations != 1 || len(executor.calls) != 0 {
						t.Fatalf("policy evaluations/executor calls = %d/%#v, want 1/none", policy.evaluations, executor.calls)
					}
				})
			}
		}
	}
}

func TestUnknownAnonymousProfileWinsOverValueValidation(t *testing.T) {
	values := []string{
		strings.Repeat("x", MaxVaultTextBytes+1),
		string([]byte{0xff}),
	}
	for _, value := range values {
		admission := testAdmission(t)
		service := New(testProfiles(), &fakeExecutor{}, nil, admission)
		lease := acquireLease(t, admission)
		_, err := service.Prepare(lease.Context(context.Background()), caller.Anonymous(), Command{Operation: OperationDecrypt, ProfileID: "missing", Value: value}, lease)
		if !HasCode(err, CodeNotFound) {
			t.Fatalf("Prepare() error = %v, want not_found", err)
		}
	}
}

func TestBearerOperationRequiresExactScopeAndCasbin(t *testing.T) {
	policy := &fakeAuthorizer{decisions: map[string]error{}}
	admission := testAdmission(t)
	service := New(testProfiles(), &fakeExecutor{}, policy, admission)
	command := Command{Operation: OperationRotate, SourceProfileID: "dev", DestinationProfileID: "prod", Value: "vault"}

	lease := acquireLease(t, admission)
	if _, err := service.Prepare(lease.Context(context.Background()), bearerCaller(t, ScopeDecrypt, ScopeEncrypt), command, lease); !HasCode(err, CodeForbidden) {
		t.Fatalf("rotate without rotate scope error = %v, want forbidden", err)
	}
	if len(policy.calls) != 0 {
		t.Fatalf("scope denial reached policy: %#v", policy.calls)
	}

	lease.Release()
	lease, err := admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	leaseContext := lease.Context(context.Background())
	prepared, err := service.Prepare(leaseContext, bearerCaller(t, ScopeRotate), command, lease)
	if err != nil {
		t.Fatalf("Prepare(rotate scope) error = %v", err)
	}
	if policy.evaluations != 1 || len(policy.calls) != 2 {
		t.Fatalf("rotate policy evaluations/calls = %d/%#v, want one evaluation with two checks", policy.evaluations, policy.calls)
	}
	if _, err := prepared.Run(leaseContext); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunRejectsUnsafeDecryptResultsAndGenericExecutorFailures(t *testing.T) {
	tests := []struct {
		name    string
		decrypt func(context.Context, string, string) (string, error)
	}{
		{name: "invalid utf8", decrypt: func(context.Context, string, string) (string, error) { return string([]byte{0xff}), nil }},
		{name: "oversized plaintext", decrypt: func(context.Context, string, string) (string, error) {
			return strings.Repeat("x", MaxPlaintextBytes+1), nil
		}},
		{name: "executor detail", decrypt: func(context.Context, string, string) (string, error) {
			return "", errors.New("wrong password: do-not-leak")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission := testAdmission(t)
			service := New(testProfiles(), &fakeExecutor{decrypt: test.decrypt}, nil, admission)
			lease := acquireLease(t, admission)
			leaseContext := lease.Context(context.Background())
			prepared, err := service.Prepare(leaseContext, caller.Anonymous(), Command{Operation: OperationDecrypt, ProfileID: "dev", Value: "secret-vault"}, lease)
			if err != nil {
				t.Fatal(err)
			}
			_, err = prepared.Run(leaseContext)
			if !HasCode(err, CodeOperationFailed) || strings.Contains(err.Error(), "do-not-leak") || strings.Contains(err.Error(), "secret-vault") {
				t.Fatalf("Run() error = %v, want safe operation_failed", err)
			}
		})
	}
}

func TestRotateRejectsUnsafeDecryptedOutputBeforeEncrypt(t *testing.T) {
	executor := &fakeExecutor{decrypt: func(context.Context, string, string) (string, error) {
		return strings.Repeat("x", MaxPlaintextBytes+1), nil
	}}
	admission := testAdmission(t)
	service := New(testProfiles(), executor, nil, admission)
	lease := acquireLease(t, admission)
	leaseContext := lease.Context(context.Background())
	prepared, err := service.Prepare(leaseContext, caller.Anonymous(), Command{
		Operation:            OperationRotate,
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Value:                "vault",
	}, lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Run(leaseContext); !HasCode(err, CodeOperationFailed) {
		t.Fatalf("Run() error = %v, want operation_failed", err)
	}
	if len(executor.calls) != 1 || executor.calls[0].operation != "decrypt" {
		t.Fatalf("executor calls = %#v, want decrypt only", executor.calls)
	}
}

func TestPrepareCancellationAfterAuthorizationFailsClosed(t *testing.T) {
	origin, cancel := context.WithCancel(context.Background())
	admission := testAdmission(t)
	lease := acquireLeaseForContext(t, admission, origin)
	bound := lease.Context(origin)
	policy := authorizerFunc(func(caller.Caller, []authz.Check) ([]bool, error) {
		cancel()
		return []bool{true}, nil
	})
	service := New(testProfiles(), &fakeExecutor{}, policy, admission)

	_, err := service.Prepare(bound, sessionCaller(t), Command{Operation: OperationDecrypt, ProfileID: "dev", Value: "vault"}, lease)
	if !HasCode(err, CodeTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Prepare() error = %v, want safe context cancellation", err)
	}
}

func TestPolicyCancellationWinsOverDecision(t *testing.T) {
	tests := []struct {
		name   string
		list   bool
		outage bool
	}{
		{name: "prepare denial"},
		{name: "prepare outage", outage: true},
		{name: "list denial", list: true},
		{name: "list outage", list: true, outage: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			executor := &fakeExecutor{}
			policy := authorizerFunc(func(_ caller.Caller, checks []authz.Check) ([]bool, error) {
				cancel()
				if test.outage {
					return nil, authz.ErrPolicy
				}
				return make([]bool, len(checks)), nil
			})
			service := New(testProfiles(), executor, policy, testAdmission(t))
			var err error
			if test.list {
				_, err = service.ListProfiles(ctx, sessionCaller(t))
			} else {
				lease := acquireLeaseForContext(t, service.Admission(), ctx)
				_, err = service.Prepare(lease.Context(ctx), sessionCaller(t), Command{Operation: OperationDecrypt, ProfileID: "dev", Value: "vault"}, lease)
			}
			if !HasCode(err, CodeTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
				t.Fatalf("operation error = %v, want safe context cancellation", err)
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", executor.calls)
			}
		})
	}
}

func TestPrepareHonorsChildCancellationDuringPolicyEvaluation(t *testing.T) {
	tests := []struct {
		name     string
		outcome  string
		deadline bool
	}{
		{name: "allow after cancel", outcome: "allow"},
		{name: "deny after cancel", outcome: "deny"},
		{name: "outage after cancel", outcome: "outage"},
		{name: "allow after deadline", outcome: "allow", deadline: true},
	}
	type prepareResult struct {
		prepared *PreparedOperation
		err      error
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin, cancelOrigin := context.WithCancel(context.Background())
			defer cancelOrigin()
			admission := testAdmission(t)
			lease, err := admission.TryAcquire(origin)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			bound := lease.Context(origin)
			started := make(chan struct{})
			release := make(chan struct{})
			policy := authorizerFunc(func(_ caller.Caller, checks []authz.Check) ([]bool, error) {
				close(started)
				<-release
				switch test.outcome {
				case "allow":
					allowed := make([]bool, len(checks))
					for index := range allowed {
						allowed[index] = true
					}
					return allowed, nil
				case "deny":
					return make([]bool, len(checks)), nil
				default:
					return nil, authz.ErrPolicy
				}
			})
			executor := &fakeExecutor{}
			service := New(testProfiles(), executor, policy, admission)
			actor := sessionCaller(t)
			var child context.Context
			var cancelChild context.CancelFunc
			if test.deadline {
				child, cancelChild = context.WithDeadline(bound, time.Now().Add(50*time.Millisecond))
			} else {
				child, cancelChild = context.WithCancel(bound)
			}
			defer cancelChild()
			result := make(chan prepareResult, 1)
			go func() {
				prepared, prepareErr := service.Prepare(child, actor, Command{Operation: OperationDecrypt, ProfileID: "dev", Value: "vault"}, lease)
				result <- prepareResult{prepared: prepared, err: prepareErr}
			}()

			select {
			case <-started:
			case <-time.After(2 * time.Second):
				close(release)
				<-result
				t.Fatal("policy evaluation did not start")
			}
			if test.deadline {
				select {
				case <-child.Done():
				case <-time.After(2 * time.Second):
					close(release)
					<-result
					t.Fatal("child deadline did not expire")
				}
			} else {
				cancelChild()
			}
			close(release)
			var outcome prepareResult
			select {
			case outcome = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("Prepare did not return after policy evaluation")
			}
			wantCause := error(context.Canceled)
			if test.deadline {
				wantCause = context.DeadlineExceeded
			}
			if outcome.prepared != nil || !HasCode(outcome.err, CodeTemporarilyUnavailable) || !errors.Is(outcome.err, wantCause) {
				t.Fatalf("Prepare() = %#v, %v, want nil safe cancellation", outcome.prepared, outcome.err)
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", executor.calls)
			}
			if origin.Err() != nil {
				t.Fatalf("origin error = %v, want live origin", origin.Err())
			}
		})
	}
}

func TestRotateStopsBetweenDecryptAndEncryptAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	executor := &fakeExecutor{decrypt: func(context.Context, string, string) (string, error) {
		cancel()
		return "plaintext", nil
	}}
	admission := testAdmission(t)
	service := New(testProfiles(), executor, nil, admission)
	lease := acquireLeaseForContext(t, admission, ctx)
	leaseContext := lease.Context(ctx)
	prepared, err := service.Prepare(leaseContext, caller.Anonymous(), Command{
		Operation:            OperationRotate,
		SourceProfileID:      "dev",
		DestinationProfileID: "prod",
		Value:                "vault",
	}, lease)
	if err != nil {
		t.Fatal(err)
	}
	_, err = prepared.Run(leaseContext)
	if !HasCode(err, CodeTemporarilyUnavailable) {
		t.Fatalf("Run() error = %v, want temporarily_unavailable", err)
	}
	if len(executor.calls) != 1 || executor.calls[0].operation != "decrypt" {
		t.Fatalf("executor calls = %#v, want decrypt only", executor.calls)
	}
}

func TestPreparedOperationCannotDetachFromOriginCancellation(t *testing.T) {
	tests := []struct {
		name      string
		detach    func(*Lease, context.Context) context.Context
		code      Code
		wantCause error
	}{
		{name: "fresh rebind", detach: func(lease *Lease, _ context.Context) context.Context { return lease.Context(context.Background()) }, code: CodeNotReady},
		{name: "without cancel", detach: func(_ *Lease, bound context.Context) context.Context { return context.WithoutCancel(bound) }, code: CodeTemporarilyUnavailable, wantCause: context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin, cancel := context.WithCancel(context.Background())
			executor := &fakeExecutor{}
			admission := testAdmission(t)
			service := New(testProfiles(), executor, nil, admission)
			lease := acquireLeaseForContext(t, admission, origin)
			bound := lease.Context(origin)
			prepared, err := service.Prepare(bound, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			_, err = prepared.Run(test.detach(lease, bound))
			if !HasCode(err, test.code) {
				t.Fatalf("Run() error = %v, want code %q", err, test.code)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("Run() error = %v, want cause %v", err, test.wantCause)
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", executor.calls)
			}
		})
	}
}

func TestPreparedOperationCannotDetachOnInitialBinding(t *testing.T) {
	tests := map[string]func(context.Context) context.Context{
		"background":     func(context.Context) context.Context { return context.Background() },
		"without cancel": context.WithoutCancel,
	}
	for name, detach := range tests {
		t.Run(name, func(t *testing.T) {
			origin, cancel := context.WithCancel(context.Background())
			admission := testAdmission(t)
			lease, err := admission.TryAcquire(origin)
			if err != nil {
				t.Fatal(err)
			}
			bound := lease.Context(detach(origin))
			executor := &fakeExecutor{}
			service := New(testProfiles(), executor, nil, admission)
			prepared, err := service.Prepare(bound, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
			if err != nil {
				lease.Release()
				t.Fatal(err)
			}
			cancel()
			_, err = prepared.Run(context.WithoutCancel(bound))
			if !HasCode(err, CodeTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
				lease.Release()
				t.Fatalf("Run() error = %v, want safe context cancellation", err)
			}
			if len(executor.calls) != 0 {
				lease.Release()
				t.Fatalf("executor calls = %#v, want none", executor.calls)
			}
			lease.Release()
			if admission.InUse() != 0 {
				t.Fatalf("admission in use = %d, want 0", admission.InUse())
			}
		})
	}
}

func TestPreparedOperationHonorsInvocationCancellationDuringExecutor(t *testing.T) {
	origin, cancelOrigin := context.WithCancel(context.Background())
	defer cancelOrigin()
	admission := testAdmission(t)
	lease, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	bound := lease.Context(origin)
	invocation, cancelInvocation := context.WithCancelCause(bound)
	started := make(chan struct{})
	unblock := make(chan struct{})
	executor := &fakeExecutor{encrypt: func(ctx context.Context, _, _ string) (string, error) {
		close(started)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-unblock:
			return "", errors.New("test executor had to be unblocked")
		}
	}}
	service := New(testProfiles(), executor, nil, admission)
	prepared, err := service.Prepare(bound, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, runErr := prepared.Run(invocation)
		result <- runErr
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(unblock)
		<-result
		lease.Release()
		t.Fatal("executor did not start")
	}
	cancelInvocation(context.DeadlineExceeded)
	select {
	case runErr := <-result:
		lease.Release()
		if !HasCode(runErr, CodeTemporarilyUnavailable) || !errors.Is(runErr, context.DeadlineExceeded) {
			t.Fatalf("Run() error = %v, want safe invocation deadline", runErr)
		}
	case <-time.After(2 * time.Second):
		close(unblock)
		runErr := <-result
		lease.Release()
		t.Fatalf("Run did not stop after invocation cancellation: %v", runErr)
	}
	if origin.Err() != nil {
		t.Fatalf("origin error = %v, want live origin", origin.Err())
	}
	if admission.InUse() != 0 {
		t.Fatalf("admission in use = %d, want 0", admission.InUse())
	}
}

func TestPreparedOperationUsesAcquisitionContextDuringDetachedRun(t *testing.T) {
	origin, cancel := context.WithCancel(context.Background())
	admission := testAdmission(t)
	lease, err := admission.TryAcquire(origin)
	if err != nil {
		t.Fatal(err)
	}
	bound := lease.Context(origin)
	started := make(chan struct{})
	unblock := make(chan struct{})
	executor := &fakeExecutor{encrypt: func(ctx context.Context, _, _ string) (string, error) {
		close(started)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-unblock:
			return "", errors.New("test executor had to be unblocked")
		}
	}}
	service := New(testProfiles(), executor, nil, admission)
	prepared, err := service.Prepare(bound, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, runErr := prepared.Run(context.WithoutCancel(bound))
		result <- runErr
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(unblock)
		<-result
		lease.Release()
		t.Fatal("executor did not start")
	}
	cancel()
	select {
	case runErr := <-result:
		lease.Release()
		if !HasCode(runErr, CodeTemporarilyUnavailable) || !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want safe context cancellation", runErr)
		}
	case <-time.After(2 * time.Second):
		close(unblock)
		runErr := <-result
		lease.Release()
		t.Fatalf("detached Run did not stop after origin cancellation: %v", runErr)
	}
	if admission.InUse() != 0 {
		t.Fatalf("admission in use = %d, want 0", admission.InUse())
	}
}

func TestCancellationWinsOverGenericExecutorFailure(t *testing.T) {
	origin, cancel := context.WithCancel(context.Background())
	executor := &fakeExecutor{encrypt: func(context.Context, string, string) (string, error) {
		cancel()
		return "", errors.New("backend detail: do-not-leak")
	}}
	admission := testAdmission(t)
	service := New(testProfiles(), executor, nil, admission)
	lease := acquireLeaseForContext(t, admission, origin)
	bound := lease.Context(origin)
	prepared, err := service.Prepare(bound, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
	if err != nil {
		t.Fatal(err)
	}
	_, err = prepared.Run(bound)
	if !HasCode(err, CodeTemporarilyUnavailable) || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("Run() error = %v, want safe cancellation", err)
	}
}

func TestPreparedOperationRejectsUnsafeEncryptOutput(t *testing.T) {
	if utf8.ValidString(string([]byte{0xff})) {
		t.Fatal("test fixture unexpectedly valid UTF-8")
	}
	tests := []struct {
		name   string
		output string
	}{
		{name: "invalid UTF-8", output: string([]byte{0xff})},
		{name: "oversized", output: strings.Repeat("x", MaxVaultTextBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{encrypt: func(context.Context, string, string) (string, error) {
				return test.output, nil
			}}
			admission := testAdmission(t)
			service := New(testProfiles(), executor, nil, admission)
			lease := acquireLease(t, admission)
			leaseContext := lease.Context(context.Background())
			prepared, err := service.Prepare(leaseContext, caller.Anonymous(), Command{Operation: OperationEncrypt, ProfileID: "dev", Value: "plaintext"}, lease)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepared.Run(leaseContext); !HasCode(err, CodeOperationFailed) {
				t.Fatalf("Run() error = %v, want operation_failed", err)
			}
		})
	}
}

func TestPublicOperationMethodsUseLeaseBoundContext(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, *Service, caller.Caller) (string, error)
		want string
	}{
		{
			name: "encrypt",
			run: func(ctx context.Context, service *Service, actor caller.Caller) (string, error) {
				return service.Encrypt(ctx, actor, "dev", "plaintext")
			},
			want: "encrypted",
		},
		{
			name: "decrypt",
			run: func(ctx context.Context, service *Service, actor caller.Caller) (string, error) {
				return service.Decrypt(ctx, actor, "dev", "vault")
			},
			want: "plaintext",
		},
		{
			name: "rotate",
			run: func(ctx context.Context, service *Service, actor caller.Caller) (string, error) {
				return service.Rotate(ctx, actor, "dev", "prod", "vault")
			},
			want: "encrypted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission := testAdmission(t)
			service := New(testProfiles(), &fakeExecutor{}, nil, admission)
			lease := acquireLease(t, admission)
			got, err := test.run(lease.Context(context.Background()), service, caller.Anonymous())
			if err != nil || got != test.want {
				t.Fatalf("operation = %q, %v, want %q", got, err, test.want)
			}
		})
	}
}

func TestCallerConversionDoesNotRequireSessionOnlyFields(t *testing.T) {
	principal := authn.Principal{Issuer: "https://issuer.example", Subject: "subject", Email: "private@example.test", Groups: []string{"operators"}}
	actor, err := caller.NewSession(principal.Issuer, principal.Subject, principal.Groups)
	if err != nil {
		t.Fatal(err)
	}
	if actor.Issuer() != principal.Issuer || actor.Subject() != principal.Subject || !reflect.DeepEqual(actor.Groups(), principal.Groups) {
		t.Fatalf("actor = %#v", actor)
	}
}
