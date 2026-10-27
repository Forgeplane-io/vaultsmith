package vaultservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

func loadedServicePolicy(t *testing.T, profiles []Profile, content string) (*authz.Authorizer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal("write synthetic policy failed")
	}
	ids := make([]string, len(profiles))
	for index, profile := range profiles {
		ids[index] = profile.ID
	}
	policy, err := authz.LoadPolicy(path, ids)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	return authorizer, path
}

func replaceServicePolicy(t *testing.T, path, content string) {
	t.Helper()
	previous, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat synthetic policy failed")
	}
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte(content), 0o600); err != nil {
		t.Fatal("write synthetic replacement failed")
	}
	changed := previous.ModTime().Add(time.Second)
	if err := os.Chtimes(replacement, changed, changed); err != nil {
		t.Fatal("change synthetic replacement metadata failed")
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal("publish synthetic replacement failed")
	}
}

func TestRotateRejectsDirectRightsWithoutAnExplicitPair(t *testing.T) {
	policy, _ := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, profile:dev, decrypt, allow\np, role:operator, profile:prod, encrypt, allow\n")
	executor := &fakeExecutor{}
	service := New(testProfiles(), executor, policy, testAdmission(t))
	lease := acquireLease(t, service.Admission())
	prepared, err := service.Prepare(lease.Context(context.Background()), sessionCaller(t), Command{
		Operation: OperationRotate, SourceProfileID: "dev", DestinationProfileID: "prod", Value: "synthetic input",
	}, lease)
	if prepared != nil || !IsPolicyDenied(err) || !HasCode(err, CodeForbidden) {
		t.Fatalf("Prepare() returned an operation or error = %v, want policy denial without a pair", err)
	}
	if len(executor.calls) != 0 {
		t.Fatal("denied rotation executed Vault work")
	}
}

func TestRotateExecutesOnlyExplicitDirectedPairs(t *testing.T) {
	profiles := []Profile{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}, {ID: "x", Label: "X"}, {ID: "y", Label: "Y"}, {ID: "z", Label: "Z"}}
	policy, _ := loadedServicePolicy(t, profiles, "g, group:operators, role:operator\np, role:operator, rotation:a:x, rotate, allow\np, role:operator, rotation:b:y, rotate, allow\np, role:operator, rotation:x:z, rotate, allow\np, role:operator, rotation:b:b, rotate, allow\n")
	for _, test := range []struct {
		name, source, destination string
		allowed                   bool
	}{
		{name: "first", source: "a", destination: "x", allowed: true},
		{name: "second", source: "b", destination: "y", allowed: true},
		{name: "following edge", source: "x", destination: "z", allowed: true},
		{name: "self", source: "b", destination: "b", allowed: true},
		{name: "reverse", source: "x", destination: "a"},
		{name: "crossed first", source: "a", destination: "y"},
		{name: "crossed second", source: "b", destination: "x"},
		{name: "transitive", source: "a", destination: "z"},
		{name: "unrelated", source: "a", destination: "b"},
		{name: "implicit self", source: "a", destination: "a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{}
			service := New(profiles, executor, policy, testAdmission(t))
			lease := acquireLease(t, service.Admission())
			result, err := service.RotateResult(lease.Context(context.Background()), sessionCaller(t), test.source, test.destination, "synthetic input", nil)
			if !test.allowed {
				if result.VaultText != "" || !IsPolicyDenied(err) || len(executor.calls) != 0 {
					t.Fatalf("denied RotateResult() returned output, executor work, or error = %v", err)
				}
				return
			}
			if err != nil || result.VaultText != "encrypted" || len(executor.calls) != 2 {
				t.Fatalf("allowed RotateResult() error = %v; executor call count = %d", err, len(executor.calls))
			}
			if executor.calls[0].operation != "decrypt" || executor.calls[0].profileID != test.source || executor.calls[1].operation != "encrypt" || executor.calls[1].profileID != test.destination {
				t.Fatal("rotation did not use the exact source and destination executors")
			}
		})
	}
}

func TestRotatePolicyTruthTableAndDirectRightsAreIndependent(t *testing.T) {
	for _, topology := range []struct {
		name, rows, allowRole, denyRole string
		groups                          []string
	}{
		{name: "same role", allowRole: "operator", denyRole: "operator", groups: []string{"operators"}},
		{name: "parent allow", rows: "g, role:operator, role:base\n", allowRole: "base", denyRole: "operator", groups: []string{"operators"}},
		{name: "parent deny", rows: "g, role:operator, role:base\n", allowRole: "operator", denyRole: "base", groups: []string{"operators"}},
		{name: "separate groups", rows: "g, group:blocked, role:block\np, role:block, rotation:prod:dev, rotate, deny\n", allowRole: "operator", denyRole: "block", groups: []string{"operators", "blocked"}},
	} {
		for _, lane := range []struct {
			name                 string
			allow, deny, allowed bool
		}{
			{name: "neither"},
			{name: "deny", deny: true},
			{name: "allow", allow: true, allowed: true},
			{name: "conflict", allow: true, deny: true},
		} {
			for _, direct := range []struct {
				name, effect string
				allowed      bool
			}{
				{name: "none"},
				{name: "allow", effect: "allow", allowed: true},
				{name: "deny", effect: "deny"},
			} {
				t.Run(topology.name+"/"+lane.name+"/direct "+direct.name, func(t *testing.T) {
					content := "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\n" + topology.rows
					if lane.allow {
						content += "p, role:" + topology.allowRole + ", rotation:dev:prod, rotate, allow\n"
					}
					if lane.deny {
						content += "p, role:" + topology.denyRole + ", rotation:dev:prod, rotate, deny\n"
					}
					if direct.effect != "" {
						content += "p, role:operator, profile:dev, decrypt, " + direct.effect + "\np, role:operator, profile:prod, encrypt, " + direct.effect + "\n"
					}
					policy, _ := loadedServicePolicy(t, testProfiles(), content)
					executor := &fakeExecutor{}
					generator := newRecordingMaterialGenerator()
					service := NewWithOptions(testProfiles(), executor, policy, testAdmission(t), ServiceOptions{Generator: generator})
					actor, err := caller.NewSession("https://issuer.example", "subject", topology.groups)
					if err != nil {
						t.Fatal("construct synthetic actor failed")
					}
					lease := acquireLease(t, service.Admission())
					bound := lease.Context(context.Background())
					_, err = service.Rotate(bound, actor, "dev", "prod", "synthetic input")
					if lane.allowed && err != nil || !lane.allowed && !IsPolicyDenied(err) {
						t.Fatalf("Rotate() error = %v, want allowed = %t", err, lane.allowed)
					}
					if !lane.allowed && len(executor.calls) != 0 {
						t.Fatal("denied rotation executed Vault work")
					}
					for _, operation := range []Operation{OperationEncrypt, OperationDecrypt} {
						executor.calls = nil
						var err error
						if operation == OperationEncrypt {
							_, err = service.Encrypt(bound, actor, "prod", "synthetic input")
						} else {
							_, err = service.Decrypt(bound, actor, "dev", "synthetic input")
						}
						if direct.allowed && err != nil || !direct.allowed && !IsPolicyDenied(err) {
							t.Fatalf("direct operation error = %v, want allowed = %t", err, direct.allowed)
						}
						if !direct.allowed && len(executor.calls) != 0 {
							t.Fatal("denied direct operation executed Vault work")
						}
					}
					if !direct.allowed {
						_, err := service.Generate(bound, actor, GenerateCommand{ProfileID: "prod", Kind: GenerateKindAgeIdentity, AgeIdentity: &AgeIdentityParameters{}})
						if !IsPolicyDenied(err) || len(generator.calls) != 0 || len(executor.calls) != 0 {
							t.Fatalf("lane-only Generate() executed work or error = %v", err)
						}
					}
				})
			}
		}
	}
}

func TestRotateBearerRequiresOnlyTheExactRotateScope(t *testing.T) {
	policy, _ := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, rotation:dev:prod, rotate, allow\n")
	for _, test := range []struct {
		name    string
		scopes  []string
		allowed bool
	}{
		{name: "rotate only", scopes: []string{ScopeRotate}, allowed: true},
		{name: "all operation scopes", scopes: []string{ScopeRotate, ScopeDecrypt, ScopeEncrypt}, allowed: true},
		{name: "direct scopes", scopes: []string{ScopeDecrypt, ScopeEncrypt}},
		{name: "wrong case", scopes: []string{"vaultsmith.Rotate"}},
		{name: "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{}
			service := New(testProfiles(), executor, policy, testAdmission(t))
			lease := acquireLease(t, service.Admission())
			_, err := service.Rotate(lease.Context(context.Background()), bearerCaller(t, test.scopes...), "dev", "prod", "synthetic input")
			if test.allowed && err != nil || !test.allowed && (!HasCode(err, CodeForbidden) || IsPolicyDenied(err)) {
				t.Fatalf("Rotate() error = %v, want scope allowed = %t", err, test.allowed)
			}
			if !test.allowed && len(executor.calls) != 0 {
				t.Fatal("scope-denied rotation executed Vault work")
			}
		})
	}
}

func TestRotateDenialAndPolicyOutageHideTargetsAndValues(t *testing.T) {
	for _, state := range []string{"denied", "invalid", "missing"} {
		for _, target := range []struct {
			name, source, destination string
		}{
			{name: "known", source: "dev", destination: "prod"},
			{name: "unknown source", source: "missing", destination: "prod"},
			{name: "unknown destination", source: "dev", destination: "missing"},
		} {
			for _, value := range []struct{ name, value string }{
				{name: "ordinary", value: "synthetic-sensitive-input"},
				{name: "invalid UTF-8", value: string([]byte{0xff})},
				{name: "oversized", value: strings.Repeat("x", MaxVaultTextBytes+1)},
			} {
				for _, actor := range []struct {
					name string
					make func(*testing.T) caller.Caller
				}{
					{name: "session", make: sessionCaller},
					{name: "bearer", make: func(t *testing.T) caller.Caller { return bearerCaller(t, ScopeRotate) }},
				} {
					t.Run(state+"/"+target.name+"/"+value.name+"/"+actor.name, func(t *testing.T) {
						policy, path := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\n")
						if state == "invalid" {
							replaceServicePolicy(t, path, "p, role:operator, rotation:dev:missing, rotate, allow\n")
						} else if state == "missing" {
							if err := os.Remove(path); err != nil {
								t.Fatal("remove synthetic policy failed")
							}
						}
						executor := &fakeExecutor{}
						service := New(testProfiles(), executor, policy, testAdmission(t))
						lease := acquireLease(t, service.Admission())
						prepared, err := service.Prepare(lease.Context(context.Background()), actor.make(t), Command{Operation: OperationRotate, SourceProfileID: target.source, DestinationProfileID: target.destination, Value: value.value}, lease)
						wantCode, wantMessage := CodeForbidden, "operation is not permitted"
						if state != "denied" {
							wantCode, wantMessage = CodeNotReady, "authorization is not ready"
						}
						if prepared != nil || !HasCode(err, wantCode) || err.Error() != wantMessage || IsPolicyDenied(err) != (state == "denied") || len(executor.calls) != 0 {
							t.Fatalf("Prepare() exposed a result/work or error = %v, want safe %s", err, wantCode)
						}
					})
				}
			}
		}
	}
	policy, _ := loadedServicePolicy(t, testProfiles(), "p, role:operator, profiles, profiles:list, allow\n")
	service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))
	lease := acquireLease(t, service.Admission())
	_, err := service.Prepare(lease.Context(context.Background()), sessionCaller(t), Command{Operation: OperationRotate, SourceProfileID: "Dev", DestinationProfileID: "prod", Value: "synthetic input"}, lease)
	if !HasCode(err, CodeInvalidRequest) || IsPolicyDenied(err) {
		t.Fatalf("malformed ID error = %v, want invalid_request", err)
	}
}

func TestOldRotationPreparationMayFinishAfterObservedRemoval(t *testing.T) {
	policy, path := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, rotation:dev:prod, rotate, allow\n")
	acquired, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	oldEvaluations := 0
	executor := &fakeExecutor{}
	oldService := New(testProfiles(), executor, authorizerFunc(func(actor caller.Caller, checks []authz.Check) ([]bool, error) {
		oldEvaluations++
		allowed, err := policy.Evaluate(actor, checks)
		close(acquired)
		<-release
		return allowed, err
	}), testAdmission(t))
	freshExecutor := &fakeExecutor{}
	freshService := New(testProfiles(), freshExecutor, policy, testAdmission(t))
	oldLease := acquireLease(t, oldService.Admission())
	oldContext := oldLease.Context(context.Background())
	actor := sessionCaller(t)
	command := Command{Operation: OperationRotate, SourceProfileID: "dev", DestinationProfileID: "prod", Value: "synthetic input"}
	type preparation struct {
		prepared *PreparedOperation
		err      error
	}
	result := make(chan preparation, 1)
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		<-finished
	})
	go func() {
		defer close(finished)
		prepared, err := oldService.Prepare(oldContext, actor, command, oldLease)
		result <- preparation{prepared: prepared, err: err}
	}()
	<-acquired
	replaceServicePolicy(t, path, "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\n")
	freshLease := acquireLease(t, freshService.Admission())
	freshContext := freshLease.Context(context.Background())
	if prepared, err := freshService.Prepare(freshContext, actor, command, freshLease); prepared != nil || !IsPolicyDenied(err) {
		t.Fatalf("removal probe error = %v, want policy denial", err)
	}
	unblock.Do(func() { close(release) })
	old := <-result
	if old.prepared == nil || old.err != nil {
		t.Fatalf("old Prepare() error = %v, want its acquired allow snapshot", old.err)
	}
	copied := *old.prepared
	if _, err := old.prepared.RunResult(oldContext); err != nil {
		t.Fatalf("old RunResult() error = %v", err)
	}
	if _, err := copied.RunResult(oldContext); !HasCode(err, CodeNotReady) {
		t.Fatalf("copied RunResult() error = %v, want one-shot rejection", err)
	}
	if oldEvaluations != 1 || len(executor.calls) != 2 {
		t.Fatal("old execution repeated authorization or Vault work")
	}
	if prepared, err := freshService.Prepare(freshContext, actor, command, freshLease); prepared != nil || !IsPolicyDenied(err) || len(freshExecutor.calls) != 0 {
		t.Fatalf("fresh Prepare() error = %v, want policy denial without execution", err)
	}
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

func TestListProfilesDirectRightsDoNotImplyRotation(t *testing.T) {
	policy, _ := loadedServicePolicy(t, testProfiles(), "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, profile:dev, decrypt, allow\np, role:operator, profile:prod, encrypt, allow\n")
	service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))
	profiles, err := service.ListProfiles(context.Background(), sessionCaller(t))
	if err != nil || len(profiles) != 2 {
		t.Fatalf("ListProfiles() error = %v; visible profiles = %d, want both direct profiles", err, len(profiles))
	}
	for _, profile := range profiles {
		if profile.Capabilities.RotateSource || profile.Capabilities.RotateDestination {
			t.Fatal("direct rights incorrectly created rotation participation")
		}
		if profile.Capabilities.RotateDestinationIDs == nil || len(profile.Capabilities.RotateDestinationIDs) != 0 {
			t.Fatal("direct-only profile must have an explicit empty destination array")
		}
	}
}

func TestListProfilesProjectsExactOrderedPairsAndExecutionParity(t *testing.T) {
	catalog := []Profile{{ID: "y", Label: "Y"}, {ID: "a", Label: "A"}, {ID: "hidden", Label: "Hidden"}, {ID: "x", Label: "X"}, {ID: "b", Label: "B"}, {ID: "z", Label: "Z"}, {ID: "direct", Label: "Direct"}}
	content := "g, group:operators, role:operator\ng, role:operator, role:base\ng, group:operators, role:block\n" +
		"p, role:base, profiles, profiles:list, allow\n" +
		"p, role:base, rotation:a:x, rotate, allow\np, role:operator, rotation:b:y, rotate, allow\n" +
		"p, role:operator, rotation:a:y, rotate, allow\np, role:operator, rotation:x:z, rotate, allow\np, role:operator, rotation:b:b, rotate, allow\n" +
		"p, role:base, rotation:a:z, rotate, allow\np, role:block, rotation:a:z, rotate, deny\n" +
		"p, role:operator, rotation:a:hidden, rotate, allow\np, role:block, rotation:a:hidden, rotate, deny\n" +
		"p, role:operator, rotation:hidden:z, rotate, allow\np, role:block, rotation:hidden:z, rotate, deny\n" +
		"p, role:operator, profile:a, decrypt, deny\np, role:operator, profile:x, encrypt, deny\np, role:operator, profile:direct, encrypt, allow\n"
	policy, _ := loadedServicePolicy(t, catalog, content)
	executor := &fakeExecutor{}
	service := New(catalog, executor, policy, testAdmission(t))
	actor := sessionCaller(t)
	got, err := service.ListProfiles(context.Background(), actor)
	want := []Profile{
		{ID: "y", Label: "Y", Capabilities: ProfileCapabilities{RotateDestination: true, RotateDestinationIDs: []string{}}},
		{ID: "a", Label: "A", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestinationIDs: []string{"y", "x"}}},
		{ID: "x", Label: "X", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"z"}}},
		{ID: "b", Label: "B", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"y", "b"}}},
		{ID: "z", Label: "Z", Capabilities: ProfileCapabilities{RotateDestination: true, RotateDestinationIDs: []string{}}},
		{ID: "direct", Label: "Direct", Capabilities: ProfileCapabilities{Encrypt: true, RotateDestinationIDs: []string{}}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListProfiles() = %#v, %v; want ordered exact relation %#v", got, err, want)
	}
	if len(executor.calls) != 0 {
		t.Fatal("profile discovery executed Vault work")
	}
	lease := acquireLease(t, service.Admission())
	bound := lease.Context(context.Background())
	for _, source := range catalog {
		for _, destination := range catalog {
			allowed := false
			for _, profile := range want {
				if profile.ID == source.ID {
					for _, id := range profile.Capabilities.RotateDestinationIDs {
						allowed = allowed || id == destination.ID
					}
				}
			}
			executor.calls = nil
			_, err := service.Rotate(bound, actor, source.ID, destination.ID, "synthetic input")
			if allowed && err != nil || !allowed && (!IsPolicyDenied(err) || len(executor.calls) != 0) {
				t.Fatalf("execution disagreed with explicit discovery for %s to %s; error = %v", source.ID, destination.ID, err)
			}
		}
	}
}

func TestListProfilesScopesKeepLaneOnlyVisibilitySeparate(t *testing.T) {
	catalog := []Profile{{ID: "dev", Label: "Development"}, {ID: "prod", Label: "Production"}, {ID: "direct", Label: "Direct"}}
	policy, _ := loadedServicePolicy(t, catalog, "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, rotation:dev:prod, rotate, allow\np, role:operator, profile:direct, encrypt, allow\np, role:operator, profile:direct, decrypt, allow\n")
	for _, test := range []struct {
		name  string
		actor caller.Caller
		want  []Profile
	}{
		{name: "session", actor: sessionCaller(t), want: []Profile{
			{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestinationIDs: []string{"prod"}}},
			{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{RotateDestination: true, RotateDestinationIDs: []string{}}},
			{ID: "direct", Label: "Direct", Capabilities: ProfileCapabilities{Encrypt: true, Decrypt: true, RotateDestinationIDs: []string{}}},
		}},
		{name: "rotate scope", actor: bearerCaller(t, ScopeProfileRead, ScopeRotate), want: []Profile{
			{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestinationIDs: []string{"prod"}}},
			{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{RotateDestination: true, RotateDestinationIDs: []string{}}},
		}},
		{name: "direct scopes without rotate", actor: bearerCaller(t, ScopeProfileRead, ScopeEncrypt, ScopeDecrypt), want: []Profile{
			{ID: "direct", Label: "Direct", Capabilities: ProfileCapabilities{Encrypt: true, Decrypt: true, RotateDestinationIDs: []string{}}},
		}},
		{name: "encrypt scope", actor: bearerCaller(t, ScopeProfileRead, ScopeEncrypt), want: []Profile{
			{ID: "direct", Label: "Direct", Capabilities: ProfileCapabilities{Encrypt: true, RotateDestinationIDs: []string{}}},
		}},
		{name: "profile read alone", actor: bearerCaller(t, ScopeProfileRead), want: []Profile{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := New(catalog, &fakeExecutor{}, policy, testAdmission(t))
			got, err := service.ListProfiles(context.Background(), test.actor)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ListProfiles() = %#v, %v; want %#v", got, err, test.want)
			}
		})
	}
	evaluations := 0
	service := New(catalog, &fakeExecutor{}, authorizerFunc(func(actor caller.Caller, checks []authz.Check) ([]bool, error) {
		evaluations++
		return policy.Evaluate(actor, checks)
	}), testAdmission(t))
	if _, err := service.ListProfiles(context.Background(), bearerCaller(t, ScopeRotate)); !HasCode(err, CodeForbidden) || evaluations != 0 {
		t.Fatalf("missing profile-read scope reached policy or error = %v", err)
	}
}

func TestListProfilesAnonymousProjectsIndependentCompleteRelations(t *testing.T) {
	service := New(testProfiles(), &fakeExecutor{}, nil, testAdmission(t))
	got, err := service.ListProfiles(context.Background(), caller.Anonymous())
	all := ProfileCapabilities{Encrypt: true, Decrypt: true, RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"dev", "prod"}}
	want := []Profile{{ID: "dev", Label: "Development", Capabilities: all}, {ID: "prod", Label: "Production", Capabilities: all}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("anonymous ListProfiles() = %#v, %v; want complete development relation", got, err)
	}
	got[0].Capabilities.RotateDestinationIDs[0] = "changed"
	if got[1].Capabilities.RotateDestinationIDs[0] != "dev" {
		t.Fatal("destination relations alias each other")
	}
	got, err = service.ListProfiles(context.Background(), caller.Anonymous())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("mutating a discovery response changed later development authority")
	}
}

func TestListProfilesPolicyRemovalClearsLastEdgeDespiteDirectRights(t *testing.T) {
	initial := "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, profile:dev, decrypt, allow\np, role:operator, profile:prod, encrypt, allow\np, role:operator, rotation:dev:prod, rotate, allow\n"
	policy, path := loadedServicePolicy(t, testProfiles(), initial)
	service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))
	got, err := service.ListProfiles(context.Background(), sessionCaller(t))
	if err != nil || len(got) != 2 || !reflect.DeepEqual(got[0].Capabilities.RotateDestinationIDs, []string{"prod"}) || !got[1].Capabilities.RotateDestination {
		t.Fatalf("initial discovery did not contain the allowed edge; error = %v", err)
	}
	replaceServicePolicy(t, path, initial+"p, role:operator, rotation:dev:prod, rotate, deny\n")
	got, err = service.ListProfiles(context.Background(), sessionCaller(t))
	want := []Profile{
		{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{Decrypt: true, RotateDestinationIDs: []string{}}},
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{Encrypt: true, RotateDestinationIDs: []string{}}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("removed edge retained participation or changed direct rights; error = %v", err)
	}
}

func TestListProfilesDistinguishesRealPolicyDenialFromUnavailablePolicy(t *testing.T) {
	initial := "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, rotation:dev:prod, rotate, allow\n"
	for _, state := range []struct {
		name, replacement string
		unavailable       bool
		remove            bool
	}{
		{name: "empty", replacement: ""},
		{name: "no profiles:list", replacement: "g, group:operators, role:operator\np, role:operator, rotation:dev:prod, rotate, allow\n"},
		{name: "denied profiles:list", replacement: initial + "p, role:operator, profiles, profiles:list, deny\n"},
		{name: "all pairs denied", replacement: initial + "p, role:operator, rotation:dev:prod, rotate, deny\n"},
		{name: "invalid", replacement: initial + "p, role:operator, rotation:dev:missing, rotate, deny\n", unavailable: true},
		{name: "missing", remove: true, unavailable: true},
	} {
		t.Run(state.name, func(t *testing.T) {
			policy, path := loadedServicePolicy(t, testProfiles(), initial)
			service := New(testProfiles(), &fakeExecutor{}, policy, testAdmission(t))
			if state.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal("remove synthetic policy failed")
				}
			} else {
				replaceServicePolicy(t, path, state.replacement)
			}
			got, err := service.ListProfiles(context.Background(), sessionCaller(t))
			if state.unavailable {
				if got != nil || !HasCode(err, CodeNotReady) || err.Error() != "authorization is not ready" {
					t.Fatalf("unavailable discovery returned a catalog or error = %v, want safe not_ready", err)
				}
			} else if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("denied discovery = %#v, %v; want explicit empty success", got, err)
			}
			if state.remove {
				if err := os.WriteFile(path, []byte(initial+"# recovered\n"), 0o600); err != nil {
					t.Fatal("restore synthetic policy failed")
				}
			} else {
				replaceServicePolicy(t, path, initial+"# recovered\n")
			}
			got, err = service.ListProfiles(context.Background(), sessionCaller(t))
			if err != nil || len(got) != 2 || !reflect.DeepEqual(got[0].Capabilities.RotateDestinationIDs, []string{"prod"}) {
				t.Fatalf("recovered discovery did not restore its edge; error = %v", err)
			}
		})
	}
}

func TestListProfilesUsesOneCoherentRealPolicyEvaluation(t *testing.T) {
	initial := "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, profile:dev, decrypt, allow\np, role:operator, rotation:dev:prod, rotate, allow\n"
	policy, path := loadedServicePolicy(t, testProfiles(), initial)
	evaluations := 0
	executor := &fakeExecutor{}
	service := New(testProfiles(), executor, authorizerFunc(func(actor caller.Caller, checks []authz.Check) ([]bool, error) {
		evaluations++
		allowed, err := policy.Evaluate(actor, checks)
		if evaluations == 1 {
			replaceServicePolicy(t, path, "g, group:operators, role:operator\np, role:operator, profiles, profiles:list, allow\np, role:operator, profile:prod, encrypt, allow\np, role:operator, rotation:prod:prod, rotate, allow\n")
			if err := policy.AuthorizeRotate(actor, "dev", "prod"); !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("replacement probe error = %v, want forbidden", err)
			}
		}
		return allowed, err
	}), testAdmission(t))
	got, err := service.ListProfiles(context.Background(), sessionCaller(t))
	want := []Profile{
		{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{Decrypt: true, RotateSource: true, RotateDestinationIDs: []string{"prod"}}},
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{RotateDestination: true, RotateDestinationIDs: []string{}}},
	}
	if err != nil || !reflect.DeepEqual(got, want) || evaluations != 1 {
		t.Fatalf("old discovery mixed snapshots or used %d evaluations; error = %v", evaluations, err)
	}
	got, err = service.ListProfiles(context.Background(), sessionCaller(t))
	want = []Profile{{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{Encrypt: true, RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"prod"}}}}
	if err != nil || !reflect.DeepEqual(got, want) || evaluations != 2 || len(executor.calls) != 0 {
		t.Fatalf("fresh discovery was incoherent or executed work; evaluations = %d, error = %v", evaluations, err)
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
	all := ProfileCapabilities{Encrypt: true, Decrypt: true, RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"dev", "prod"}}
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
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{Encrypt: true, RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"dev", "prod"}}},
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
		{ID: "dev", Label: "Development", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"dev", "prod"}}},
		{ID: "prod", Label: "Production", Capabilities: ProfileCapabilities{RotateSource: true, RotateDestination: true, RotateDestinationIDs: []string{"dev", "prod"}}},
	}
	if !reflect.DeepEqual(rotateOnly, wantBearer) {
		t.Fatalf("bearer profiles = %#v, want %#v", rotateOnly, wantBearer)
	}

	if _, err := service.ListProfiles(context.Background(), bearerCaller(t, ScopeEncrypt)); !HasCode(err, CodeForbidden) {
		t.Fatalf("bearer listing without profile scope error = %v, want forbidden", err)
	}
}

func TestPreflightProfilesOwnsFixedScopeDecision(t *testing.T) {
	service := New(testProfiles(), &fakeExecutor{}, &fakeAuthorizer{}, testAdmission(t))
	if err := service.PreflightProfiles(context.Background(), bearerCaller(t, ScopeEncrypt)); !HasCode(err, CodeForbidden) {
		t.Fatalf("PreflightProfiles() error = %v, want forbidden", err)
	}
	if err := service.PreflightProfiles(context.Background(), bearerCaller(t, ScopeProfileRead)); err != nil {
		t.Fatalf("PreflightProfiles(profile scope) error = %v", err)
	}
	if err := service.PreflightProfiles(context.Background(), caller.Anonymous()); err != nil {
		t.Fatalf("PreflightProfiles(anonymous) error = %v", err)
	}
}

func TestPrepareMarksOnlyPolicyDenial(t *testing.T) {
	deniedPolicy := &fakeAuthorizer{decisions: map[string]error{
		authz.ActionEncrypt + "\x00" + authz.ProfileResource("dev"): authz.ErrForbidden,
	}}
	deniedService := New(testProfiles(), &fakeExecutor{}, deniedPolicy, testAdmission(t))
	deniedLease := acquireLease(t, deniedService.Admission())
	deniedContext := deniedLease.Context(context.Background())
	_, err := deniedService.Prepare(deniedContext, bearerCaller(t, ScopeEncrypt), Command{
		Operation: OperationEncrypt,
		ProfileID: "dev",
		Value:     "synthetic",
	}, deniedLease)
	if !IsPolicyDenied(err) || !HasCode(err, CodeForbidden) {
		t.Fatalf("Prepare(policy denied) error = %v, want typed forbidden policy denial", err)
	}

	scopeService := New(testProfiles(), &fakeExecutor{}, &fakeAuthorizer{}, testAdmission(t))
	scopeLease := acquireLease(t, scopeService.Admission())
	scopeContext := scopeLease.Context(context.Background())
	_, err = scopeService.Prepare(scopeContext, bearerCaller(t, ScopeProfileRead), Command{
		Operation: OperationEncrypt,
		ProfileID: "dev",
		Value:     "synthetic",
	}, scopeLease)
	if IsPolicyDenied(err) || !HasCode(err, CodeForbidden) {
		t.Fatalf("Prepare(scope denied) error = %v, want untyped forbidden scope denial", err)
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
	if policy.evaluations != 1 || !reflect.DeepEqual(policy.calls, []authorizationCall{{kind: caller.KindBearer, action: authz.ActionRotate, resource: authz.RotationResource("dev", "prod")}}) {
		t.Fatalf("rotate policy evaluations/calls = %d/%#v, want one exact pair check", policy.evaluations, policy.calls)
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
	for _, test := range []struct {
		name      string
		plaintext string
		err       error
	}{
		{name: "oversized", plaintext: strings.Repeat("x", MaxPlaintextBytes+1)},
		{name: "invalid UTF-8", plaintext: string([]byte{0xff, 0xfe, 0xfd})},
		{name: "executor failure", err: errors.New("synthetic-sensitive-executor-detail")},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{decrypt: func(context.Context, string, string) (string, error) {
				return test.plaintext, test.err
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
			output, err := prepared.Run(leaseContext)
			if output != "" || !HasCode(err, CodeOperationFailed) || err.Error() != "vault operation failed" {
				t.Fatalf("Run() returned output or an unsafe error: %v", err)
			}
			if len(executor.calls) != 1 || executor.calls[0].operation != "decrypt" {
				t.Fatalf("executor calls = %#v, want decrypt only", executor.calls)
			}
		})
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
