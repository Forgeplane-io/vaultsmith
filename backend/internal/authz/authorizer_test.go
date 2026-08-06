package authz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
)

func policyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func principalWithGroups(groups ...string) authn.Principal {
	return authn.Principal{Issuer: "https://issuer", Subject: "subject", Groups: groups}
}

func TestAuthorizerEnforcesGroupsRolesDenyAndProfileFiltering(t *testing.T) {
	path := policyFile(t, strings.TrimSpace(`
 g, group:admins, role:admin
 g, group:readers, role:reader
 g, role:reader, role:base
 p, role:admin, profiles, profiles:list, allow
 p, role:admin, profile:dev, encrypt, allow
 p, role:admin, profile:dev, decrypt, allow
 p, role:admin, profile:prod, encrypt, allow
 p, role:base, profiles, profiles:list, allow
 p, role:base, profile:dev, decrypt, allow
 p, role:reader, profile:dev, decrypt, deny
 p, role:reader, profile:stage*, decrypt, allow
 `))
	policy, err := LoadPolicy(path, []string{"dev", "prod", "stageblue"})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	admin := principalWithGroups("admins")
	if err := authorizer.Authorize(admin, ActionEncrypt, ProfileResource("dev")); err != nil {
		t.Fatalf("admin encrypt dev: %v", err)
	}
	if err := authorizer.AuthorizeRotate(admin, "dev", "prod"); err != nil {
		t.Fatalf("admin rotate: %v", err)
	}
	reader := principalWithGroups("readers")
	if err := authorizer.Authorize(reader, ActionDecrypt, ProfileResource("dev")); err == nil {
		t.Fatal("reader decrypt dev allowed despite explicit deny")
	}
	if err := authorizer.Authorize(reader, ActionDecrypt, ProfileResource("stageblue")); err != nil {
		t.Fatalf("reader decrypt stageblue: %v", err)
	}
	got := authorizer.FilterProfiles(reader, []string{"dev", "prod", "stageblue"})
	if want := []string{"stageblue"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterProfiles() = %#v, want %#v", got, want)
	}
}

func TestAuthorizeRotateUsesOnePolicySnapshot(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, allow\n"
	path := policyFile(t, initial)
	policy, err := LoadPolicy(path, []string{"dev", "prod"})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}

	var rewrite sync.Once
	authorizer.policy.enforcer.AddFunction("vaultsmithMatch", func(args ...interface{}) (interface{}, error) {
		rewrite.Do(func() {
			updated := "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, deny\n"
			if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
				t.Errorf("rewrite policy: %v", err)
			}
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
	policy, err := LoadPolicy(path, []string{"dev"})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	if authorizer.Can(principalWithGroups("unknown"), ActionEncrypt, ProfileResource("dev")) {
		t.Fatal("unknown group was authorized")
	}
}

func TestAuthorizerReloadsChangedPolicyFile(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, allow\n")
	policy, err := LoadPolicy(path, []string{"dev"})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	authorizer, err := NewAuthorizer(policy)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	principal := principalWithGroups("admins")
	if err := authorizer.Authorize(principal, ActionEncrypt, ProfileResource("dev")); err != nil {
		t.Fatalf("initial authorization: %v", err)
	}
	updated := "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, deny\n"
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("touch updated policy: %v", err)
	}
	if err := authorizer.Authorize(principal, ActionEncrypt, ProfileResource("dev")); err != ErrForbidden {
		t.Fatalf("authorization after policy update = %v, want ErrForbidden", err)
	}
}
