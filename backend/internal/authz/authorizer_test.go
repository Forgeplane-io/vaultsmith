package authz

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
)

func policyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func principalWithGroups(groups ...string) caller.Caller {
	actor, err := caller.NewSession("https://issuer", "subject", groups)
	if err != nil {
		panic(err)
	}
	return actor
}

func loadAuthorizer(t *testing.T, path string, profileIDs []string) *Authorizer {
	t.Helper()
	policy, err := LoadPolicy(path, profileIDs)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	return authorizer
}

func capabilitiesForProfiles(t *testing.T, authorizer *Authorizer, principal caller.Caller, profileIDs []string) map[string]ProfileCapabilities {
	t.Helper()
	capabilities, err := authorizer.CapabilitiesForProfiles(principal, profileIDs)
	if err != nil {
		t.Fatalf("CapabilitiesForProfiles() error = %v", err)
	}
	return capabilities
}

func replacePolicyMatcher(t *testing.T, authorizer *Authorizer, path string, matcher func(...interface{}) (interface{}, error)) {
	t.Helper()
	m, err := model.NewModelFromString(embeddedModel)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewEnforcer(m, fileadapter.NewAdapter(path))
	if err != nil {
		t.Fatal(err)
	}
	enforcer.AddFunction("vaultsmithHasRole", matchPolicyRole)
	enforcer.AddFunction("vaultsmithMatch", matcher)
	authorizer.policy.enforcer = enforcer
}

func TestNewAuthorizerRejectsUninitializedPolicy(t *testing.T) {
	_, err := NewAuthorizer(&Policy{})
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("NewAuthorizer() error = %v, want %v", err, ErrPolicy)
	}
}

func TestAuthorizerEnforcesGroupsRolesDenyAndProfileFiltering(t *testing.T) {
	path := policyFile(t, strings.TrimSpace(`
 g, group:admins, role:admin
 g, group:readers, role:reader
 g, group:nolisters, role:nolister
 g, role:reader, role:base
 p, role:admin, profiles, profiles:list, allow
 p, role:admin, profile:dev, encrypt, allow
 p, role:admin, profile:dev, decrypt, allow
 p, role:admin, profile:prod, encrypt, allow
 p, role:admin, profile:prod, decrypt, deny
 p, role:nolister, profile:dev, encrypt, allow
 p, role:base, profiles, profiles:list, allow
 p, role:base, profile:dev, decrypt, allow
 p, role:reader, profile:dev, decrypt, deny
 p, role:reader, profile:stage*, decrypt, allow
 `))
	authorizer := loadAuthorizer(t, path, []string{"dev", "prod", "stageblue"})
	admin := principalWithGroups("admins")
	if err := authorizer.Authorize(admin, ActionEncrypt, ProfileResource("dev")); err != nil {
		t.Fatalf("admin encrypt dev: %v", err)
	}
	if err := authorizer.AuthorizeRotate(admin, "dev", "prod"); err != nil {
		t.Fatalf("admin rotate: %v", err)
	}
	if got, want := capabilitiesForProfiles(t, authorizer, admin, []string{"dev", "prod", "stageblue"}), map[string]ProfileCapabilities{
		"dev":  {Encrypt: true, Decrypt: true},
		"prod": {Encrypt: true},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CapabilitiesForProfiles(admin) = %#v, want %#v", got, want)
	}
	reader := principalWithGroups("readers")
	if err := authorizer.Authorize(reader, ActionDecrypt, ProfileResource("dev")); err == nil {
		t.Fatal("reader decrypt dev allowed despite explicit deny")
	}
	if err := authorizer.Authorize(principalWithGroups("admins", "readers"), ActionDecrypt, ProfileResource("dev")); !errors.Is(err, ErrForbidden) {
		t.Fatalf("conflicting roles error = %v, want %v", err, ErrForbidden)
	}
	if err := authorizer.Authorize(reader, ActionDecrypt, ProfileResource("stageblue")); err != nil {
		t.Fatalf("reader decrypt stageblue: %v", err)
	}
	got := capabilitiesForProfiles(t, authorizer, reader, []string{"dev", "prod", "stageblue"})
	if want := map[string]ProfileCapabilities{"stageblue": {Decrypt: true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CapabilitiesForProfiles(reader) = %#v, want %#v", got, want)
	}
	if got := capabilitiesForProfiles(t, authorizer, principalWithGroups("unknown"), []string{"dev"}); len(got) != 0 {
		t.Fatalf("CapabilitiesForProfiles(unknown) = %#v, want no visible profiles", got)
	}
	if got := capabilitiesForProfiles(t, authorizer, principalWithGroups("nolisters"), []string{"dev"}); len(got) != 0 {
		t.Fatalf("CapabilitiesForProfiles(nolister) = %#v, want no visible profiles without profiles:list", got)
	}
}

func TestProfileCapabilitiesUseOnePolicySnapshot(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, encrypt, allow\np, role:admin, profile:dev, decrypt, allow\n"
	path := policyFile(t, initial)
	authorizer := loadAuthorizer(t, path, []string{"dev"})

	var rewrite sync.Once
	rewritten := false
	replacePolicyMatcher(t, authorizer, path, func(args ...interface{}) (interface{}, error) {
		rewrite.Do(func() {
			updated := "g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, encrypt, allow\np, role:admin, profile:dev, decrypt, deny\n"
			if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
				t.Errorf("rewrite policy: %v", err)
				return
			}
			rewritten = true
		})
		resource, resourceOK := args[0].(string)
		selector, selectorOK := args[1].(string)
		if !resourceOK || !selectorOK {
			return false, nil
		}
		return matchesPolicyObject(resource, selector), nil
	})

	got := capabilitiesForProfiles(t, authorizer, principalWithGroups("admins"), []string{"dev"})
	want := map[string]ProfileCapabilities{"dev": {Encrypt: true, Decrypt: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CapabilitiesForProfiles() = %#v, want one consistent pre-reload snapshot %#v", got, want)
	}
	if !rewritten {
		t.Fatal("policy rewrite hook was not exercised")
	}
}

func TestAuthorizeRotateUsesOnePolicySnapshot(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, allow\n"
	path := policyFile(t, initial)
	authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})

	var rewrite sync.Once
	rewritten := false
	replacePolicyMatcher(t, authorizer, path, func(args ...interface{}) (interface{}, error) {
		rewrite.Do(func() {
			updated := "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, deny\n"
			if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
				t.Errorf("rewrite policy: %v", err)
				return
			}
			rewritten = true
		})
		resource, resourceOK := args[0].(string)
		selector, selectorOK := args[1].(string)
		if !resourceOK || !selectorOK {
			return false, nil
		}
		return matchesPolicyObject(resource, selector), nil
	})

	if err := authorizer.AuthorizeRotate(principalWithGroups("admins"), "dev", "prod"); err != nil {
		t.Fatalf("AuthorizeRotate() error = %v, want one consistent pre-reload snapshot", err)
	}
	if !rewritten {
		t.Fatal("policy rewrite hook was not exercised")
	}
}

func TestAuthorizeReturnsPolicyErrorWhenMatcherFails(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev"})
	replacePolicyMatcher(t, authorizer, path, func(...interface{}) (interface{}, error) {
		return false, errors.New("matcher failed")
	})
	if err := authorizer.Authorize(principalWithGroups("admins"), ActionEncrypt, ProfileResource("dev")); !errors.Is(err, ErrPolicy) {
		t.Fatalf("Authorize() error = %v, want %v", err, ErrPolicy)
	}
}

func TestProfileCapabilitiesDistinguishDenialFromPolicyFailure(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, encrypt, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev"})

	capabilities, err := authorizer.CapabilitiesForProfiles(principalWithGroups("unknown"), []string{"dev"})
	if err != nil || len(capabilities) != 0 {
		t.Fatalf("denied capabilities = %#v, %v; want empty success", capabilities, err)
	}

	replacePolicyMatcher(t, authorizer, path, func(...interface{}) (interface{}, error) {
		return false, errors.New("matcher failed")
	})
	if _, err := authorizer.CapabilitiesForProfiles(principalWithGroups("admins"), []string{"dev"}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("CapabilitiesForProfiles() list error = %v, want %v", err, ErrPolicy)
	}

	replacePolicyMatcher(t, authorizer, path, func(args ...interface{}) (interface{}, error) {
		resource, _ := args[0].(string)
		selector, _ := args[1].(string)
		if resource == ResourceProfiles {
			return matchesPolicyObject(resource, selector), nil
		}
		return false, errors.New("matcher failed")
	})
	if _, err := authorizer.CapabilitiesForProfiles(principalWithGroups("admins"), []string{"dev"}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("CapabilitiesForProfiles() profile error = %v, want %v", err, ErrPolicy)
	}
}

func TestLoadPolicyRejectsUnsafeOrStaleSelectors(t *testing.T) {
	tests := []struct {
		name string
		row  string
	}{
		{"global profile wildcard", "p, role:admin, profile:*, encrypt, allow"},
		{"unknown profile", "p, role:admin, profile:missing, encrypt, allow"},
		{"middle wildcard", "p, role:admin, profile:d*v, encrypt, allow"},
		{"unknown action", "p, role:admin, profile:dev, all, allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := policyFile(t, "p, role:admin, profiles, profiles:list, allow\n"+tt.row+"\n")
			if _, err := LoadPolicy(path, []string{"dev"}); err == nil {
				t.Fatal("LoadPolicy() error = nil")
			}
		})
	}
}

func TestLoadPolicyRejectsRoleCyclesAndDeepInheritance(t *testing.T) {
	tests := []string{
		"g, role:a, role:b\ng, role:b, role:a\np, role:a, profiles, profiles:list, allow\n",
		"g, role:a, role:b\ng, role:b, role:c\np, role:a, profiles, profiles:list, allow\n",
	}
	for _, content := range tests {
		path := policyFile(t, content)
		if _, err := LoadPolicy(path, []string{"dev"}); err == nil {
			t.Fatal("LoadPolicy() error = nil")
		}
	}
}

func TestAuthorizerIsFailClosedForUnknownGroups(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev"})
	if err := authorizer.Authorize(principalWithGroups("unknown"), ActionEncrypt, ProfileResource("dev")); err == nil {
		t.Fatal("unknown group was authorized")
	}
}

func TestAuthorizerReloadsChangedPolicyFile(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev"})
	principal := principalWithGroups("admins")
	if err := authorizer.Authorize(principal, ActionEncrypt, ProfileResource("dev")); err != nil {
		t.Fatalf("initial authorization: %v", err)
	}
	updated := "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, deny\n"
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}
	if err := authorizer.Authorize(principal, ActionEncrypt, ProfileResource("dev")); err != ErrForbidden {
		t.Fatalf("authorization after policy update = %v, want ErrForbidden", err)
	}
}
