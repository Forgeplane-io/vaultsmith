package authz

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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

func replacePolicyFile(t *testing.T, path, content string) {
	t.Helper()
	previous, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat policy before replacement failed")
	}
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte(content), 0o600); err != nil {
		t.Fatal("write policy replacement failed")
	}
	changed := previous.ModTime().Add(time.Second)
	if err := os.Chtimes(replacement, changed, changed); err != nil {
		t.Fatal("change policy replacement metadata failed")
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal("publish policy replacement failed")
	}
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
 p, role:admin, rotation:dev:prod, rotate, allow
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

func TestAuthorizeRotateRequiresExplicitPairDespiteDirectRights(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})
	if err := authorizer.AuthorizeRotate(principalWithGroups("admins"), "dev", "prod"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("AuthorizeRotate() error = %v, want ErrForbidden without an explicit pair", err)
	}
}

func TestAuthorizeRotateAllowsOnlyExactDirectedConfiguredPairs(t *testing.T) {
	path := policyFile(t, strings.Join([]string{
		"g, group:admins, role:admin",
		"p, role:admin, rotation:a:x, rotate, allow",
		"p, role:admin, rotation:b:y, rotate, allow",
		"p, role:admin, rotation:x:z, rotate, allow",
		"p, role:admin, rotation:b:b, rotate, allow",
	}, "\n"))
	authorizer := loadAuthorizer(t, path, []string{"a", "b", "x", "y", "z"})
	actor := principalWithGroups("admins")
	for _, test := range []struct {
		name        string
		source      string
		destination string
		allowed     bool
	}{
		{name: "first pair", source: "a", destination: "x", allowed: true},
		{name: "second pair", source: "b", destination: "y", allowed: true},
		{name: "following edge", source: "x", destination: "z", allowed: true},
		{name: "explicit self pair", source: "b", destination: "b", allowed: true},
		{name: "reverse", source: "x", destination: "a"},
		{name: "crossed first", source: "a", destination: "y"},
		{name: "crossed second", source: "b", destination: "x"},
		{name: "transitive", source: "a", destination: "z"},
		{name: "unrelated", source: "a", destination: "b"},
		{name: "implicit source self pair", source: "a", destination: "a"},
		{name: "implicit intermediate self pair", source: "x", destination: "x"},
		{name: "unknown source", source: "missing", destination: "x"},
		{name: "unknown destination", source: "a", destination: "missing"},
		{name: "missing source", destination: "x"},
		{name: "malformed source", source: "a:x", destination: "z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.AuthorizeRotate(actor, test.source, test.destination)
			if test.allowed && err != nil || !test.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("AuthorizeRotate() error = %v, want allowed = %t", err, test.allowed)
			}
			got, err := authorizer.Evaluate(actor, []Check{{Action: ActionRotate, Resource: RotationResource(test.source, test.destination)}})
			if err != nil || !reflect.DeepEqual(got, []bool{test.allowed}) {
				t.Fatalf("Evaluate() = %v, %v; want [%t], nil", got, err, test.allowed)
			}
		})
	}
}

func TestRotateTruthTableKeepsDirectPermissionsIndependent(t *testing.T) {
	for _, pair := range []struct {
		name        string
		destination string
	}{
		{name: "directed", destination: "prod"},
		{name: "self", destination: "dev"},
	} {
		for _, lane := range []struct {
			name    string
			effects []string
			allowed bool
		}{
			{name: "no allow or deny"},
			{name: "deny only", effects: []string{"deny"}},
			{name: "allow only", effects: []string{"allow"}, allowed: true},
			{name: "allow and deny", effects: []string{"allow", "deny"}},
		} {
			for _, direct := range []struct {
				name    string
				effects []string
				allowed bool
			}{
				{name: "no direct rights"},
				{name: "direct allows", effects: []string{"allow"}, allowed: true},
				{name: "direct denies", effects: []string{"deny"}},
				{name: "direct conflict", effects: []string{"allow", "deny"}},
			} {
				t.Run(pair.name+"/"+lane.name+"/"+direct.name, func(t *testing.T) {
					rows := []string{"g, group:admins, role:admin", "p, role:admin, profiles, profiles:list, allow"}
					for _, effect := range lane.effects {
						rows = append(rows, "p, role:admin, rotation:dev:"+pair.destination+", rotate, "+effect)
					}
					for _, effect := range direct.effects {
						rows = append(rows, "p, role:admin, profile:dev, decrypt, "+effect,
							"p, role:admin, profile:"+pair.destination+", encrypt, "+effect)
					}
					authorizer := loadAuthorizer(t, policyFile(t, strings.Join(rows, "\n")), []string{"dev", "prod"})
					actor := principalWithGroups("admins")
					got, err := authorizer.Evaluate(actor, []Check{
						{Action: ActionRotate, Resource: RotationResource("dev", pair.destination)},
						{Action: ActionDecrypt, Resource: ProfileResource("dev")},
						{Action: ActionEncrypt, Resource: ProfileResource(pair.destination)},
					})
					want := []bool{lane.allowed, direct.allowed, direct.allowed}
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("Evaluate() = %v, %v; want %v, nil", got, err, want)
					}
					err = authorizer.AuthorizeRotate(actor, "dev", pair.destination)
					if lane.allowed && err != nil || !lane.allowed && !errors.Is(err, ErrForbidden) {
						t.Fatalf("AuthorizeRotate() error = %v, want allowed = %t", err, lane.allowed)
					}
				})
			}
		}
	}
}

func TestRotateHonorsInheritedAndSeparateGroupConflicts(t *testing.T) {
	for _, test := range []struct {
		name    string
		rows    string
		groups  []string
		allowed bool
	}{
		{name: "inherited allow", rows: "g, group:admins, role:child\ng, role:child, role:base\np, role:base, rotation:dev:prod, rotate, allow\n", groups: []string{"admins"}, allowed: true},
		{name: "inherited deny", rows: "g, group:admins, role:child\ng, role:child, role:base\np, role:child, rotation:dev:prod, rotate, allow\np, role:base, rotation:dev:prod, rotate, deny\n", groups: []string{"admins"}},
		{name: "child deny", rows: "g, group:admins, role:child\ng, role:child, role:base\np, role:base, rotation:dev:prod, rotate, allow\np, role:child, rotation:dev:prod, rotate, deny\n", groups: []string{"admins"}},
		{name: "separate group allow", rows: "g, group:admins, role:grant\ng, group:blocked, role:block\np, role:grant, rotation:dev:prod, rotate, allow\np, role:block, rotation:dev:prod, rotate, deny\n", groups: []string{"admins"}, allowed: true},
		{name: "separate group conflict", rows: "g, group:admins, role:grant\ng, group:blocked, role:block\np, role:grant, rotation:dev:prod, rotate, allow\np, role:block, rotation:dev:prod, rotate, deny\n", groups: []string{"admins", "blocked"}},
		{name: "same group conflict", rows: "g, group:admins, role:grant\ng, group:admins, role:block\np, role:grant, rotation:dev:prod, rotate, allow\np, role:block, rotation:dev:prod, rotate, deny\n", groups: []string{"admins"}},
		{name: "unrelated deny", rows: "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\np, role:admin, rotation:prod:dev, rotate, deny\n", groups: []string{"admins"}, allowed: true},
		{name: "unknown group", rows: "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\n", groups: []string{"unknown"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := loadAuthorizer(t, policyFile(t, test.rows), []string{"dev", "prod"})
			err := authorizer.AuthorizeRotate(principalWithGroups(test.groups...), "dev", "prod")
			if test.allowed && err != nil || !test.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("AuthorizeRotate() error = %v, want allowed = %t", err, test.allowed)
			}
		})
	}
}

func TestLoadPolicyRejectsModelAssertionRows(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\n"
	for _, rowType := range []string{"r", "e", "m"} {
		t.Run(rowType, func(t *testing.T) {
			path := policyFile(t, initial)
			authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})
			actor := principalWithGroups("admins")
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); err != nil {
				t.Fatalf("initial AuthorizeRotate() error = %v", err)
			}
			replacePolicyFile(t, path, initial+rowType+", role:admin, rotation:dev:prod, rotate, deny\n")
			policy, err := LoadPolicy(path, []string{"dev", "prod"})
			if policy != nil || !errors.Is(err, ErrPolicy) {
				t.Errorf("LoadPolicy() returned a policy or error = %v, want nil and ErrPolicy", err)
			}
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); !errors.Is(err, ErrPolicy) {
				t.Errorf("replaced AuthorizeRotate() error = %v, want ErrPolicy", err)
			}
		})
	}
}

func TestLoadPolicyRejectsRawDuplicatePermissionRows(t *testing.T) {
	for _, test := range []struct {
		name string
		row  string
	}{
		{name: "rotation allow", row: "p, role:admin, rotation:dev:prod, rotate, allow"},
		{name: "rotation deny", row: "p, role:admin, rotation:dev:prod, rotate, deny"},
		{name: "direct permission", row: "p, role:admin, profile:dev, decrypt, allow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := "g, group:admins, role:admin\n" + test.row + "\n" + test.row + "\n"
			policy, err := LoadPolicy(policyFile(t, content), []string{"dev", "prod"})
			if policy != nil || !errors.Is(err, ErrPolicy) {
				t.Fatalf("LoadPolicy() returned a policy or error = %v, want duplicate rejection", err)
			}
		})
	}
}

func TestLoadPolicyRejectsCollidingRawRecords(t *testing.T) {
	for _, test := range []struct {
		name      string
		initial   string
		malformed string
	}{
		{
			name:      "permission object",
			initial:   "g, group:admins, \"role:team,one\"\np, \"role:team,one\", rotation:dev:prod, rotate, allow\n",
			malformed: "p, role:team, \"one,rotation:dev:prod\", rotate, allow\n",
		},
		{
			name:      "grouping target",
			initial:   "g, group:admins, \"role:team,group:one\"\np, \"role:team,group:one\", rotation:dev:prod, rotate, allow\n",
			malformed: "g, \"group:admins,role:team\", group:one\n",
		},
		{
			name:      "grouping field count",
			initial:   "g, group:admins, \"role:team,one\"\np, \"role:team,one\", rotation:dev:prod, rotate, allow\n",
			malformed: "g, group:admins, role:team, one\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := policyFile(t, test.initial)
			authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})
			actor := principalWithGroups("admins")
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); err != nil {
				t.Fatalf("initial AuthorizeRotate() error = %v", err)
			}
			replacePolicyFile(t, path, test.initial+test.malformed)
			policy, err := LoadPolicy(path, []string{"dev", "prod"})
			if policy != nil || !errors.Is(err, ErrPolicy) {
				t.Errorf("LoadPolicy() returned a policy or error = %v, want nil and ErrPolicy", err)
			}
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); !errors.Is(err, ErrPolicy) {
				t.Errorf("replaced AuthorizeRotate() error = %v, want ErrPolicy", err)
			}
		})
	}
}

func TestLoadPolicyPreservesQuotedRolesAndGroupingDuplicates(t *testing.T) {
	content := "g, group:admins, \"role:team,one\"\ng, group:admins, \"role:team,one\"\n" +
		"g, \"role:team,one\", \"role:base,two\"\ng, \"role:team,one\", \"role:base,two\"\n" +
		"p, \"role:base,two\", rotation:dev:prod, rotate, allow\n" +
		"p, \"role:base,two\", profile:prod, encrypt, allow\n"
	authorizer := loadAuthorizer(t, policyFile(t, content), []string{"dev", "prod"})
	got, err := authorizer.Evaluate(principalWithGroups("admins"), []Check{
		{Action: ActionRotate, Resource: RotationResource("dev", "prod")},
		{Action: ActionEncrypt, Resource: ProfileResource("prod")},
		{Action: ActionDecrypt, Resource: ProfileResource("dev")},
	})
	if want := []bool{true, true, false}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Evaluate() = %v, %v; want %v, nil", got, err, want)
	}
}

func TestLoadPolicyPreservesCSVCommentsWhitespaceAndQuotedRecords(t *testing.T) {
	content := "  # synthetic policy\r\n\r\n  g, group:admins, role:admin\r\n" +
		"p, role:admin, \"rotation:dev:prod\", rotate, allow\r\n" +
		"p, role:admin, profile:dev*, decrypt, allow\r\n" +
		"p, role:admin, profile:prod, encrypt, allow"
	authorizer := loadAuthorizer(t, policyFile(t, content), []string{"dev", "prod"})
	got, err := authorizer.Evaluate(principalWithGroups("admins"), []Check{
		{Action: ActionRotate, Resource: RotationResource("dev", "prod")},
		{Action: ActionDecrypt, Resource: ProfileResource("dev")},
		{Action: ActionEncrypt, Resource: ProfileResource("prod")},
	})
	if want := []bool{true, true, true}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Evaluate() = %v, %v; want %v, nil", got, err, want)
	}
}

func TestLoadPolicyRejectsMalformedRotationRows(t *testing.T) {
	for _, test := range []struct {
		name string
		row  string
	}{
		{name: "no endpoints", row: "p, role:admin, rotation:, rotate, allow"},
		{name: "missing destination", row: "p, role:admin, rotation:dev, rotate, allow"},
		{name: "empty source", row: "p, role:admin, rotation::prod, rotate, allow"},
		{name: "empty destination", row: "p, role:admin, rotation:dev:, rotate, allow"},
		{name: "extra endpoint", row: "p, role:admin, rotation:dev:prod:dev, rotate, allow"},
		{name: "source wildcard", row: "p, role:admin, rotation:dev*:prod, rotate, allow"},
		{name: "destination wildcard", row: "p, role:admin, rotation:dev:prod*, rotate, allow"},
		{name: "global wildcard", row: "p, role:admin, rotation:*:*, rotate, allow"},
		{name: "unknown source", row: "p, role:admin, rotation:missing:prod, rotate, allow"},
		{name: "unknown destination", row: "p, role:admin, rotation:dev:missing, rotate, allow"},
		{name: "invalid source", row: "p, role:admin, rotation:Dev:prod, rotate, allow"},
		{name: "invalid destination", row: "p, role:admin, rotation:dev:../prod, rotate, allow"},
		{name: "rotate global resource", row: "p, role:admin, profiles, rotate, allow"},
		{name: "rotate profile resource", row: "p, role:admin, profile:dev, rotate, allow"},
		{name: "rotate profile prefix", row: "p, role:admin, profile:dev*, rotate, allow"},
		{name: "lane encrypt", row: "p, role:admin, rotation:dev:prod, encrypt, allow"},
		{name: "lane decrypt", row: "p, role:admin, rotation:dev:prod, decrypt, allow"},
		{name: "lane list", row: "p, role:admin, rotation:dev:prod, profiles:list, allow"},
		{name: "unknown action", row: "p, role:admin, rotation:dev:prod, Rotate, allow"},
		{name: "invalid effect", row: "p, role:admin, rotation:dev:prod, rotate, Allow"},
		{name: "group permission subject", row: "p, group:admins, rotation:dev:prod, rotate, allow"},
		{name: "empty role subject", row: "p, role:, rotation:dev:prod, rotate, allow"},
		{name: "missing effect field", row: "p, role:admin, rotation:dev:prod, rotate"},
		{name: "extra field", row: "p, role:admin, rotation:dev:prod, rotate, allow, ignored"},
		{name: "unterminated CSV quote", row: "p, role:admin, \"rotation:dev:prod, rotate, allow"},
		{name: "unknown policy type", row: "p2, role:admin, rotation:dev:prod, rotate, deny"},
		{name: "empty policy type", row: ", role:admin, rotation:dev:prod, rotate, deny"},
		{name: "unknown grouped role", row: "g, group:others, role:missing"},
		{name: "invalid grouping", row: "g, group:others, group:admins"},
		{name: "extra grouping field", row: "g, group:others, role:admin, ignored"},
		{name: "multiple role parents", row: "g, role:child, role:admin\ng, role:child, role:other"},
		{name: "deep inheritance", row: "g, role:child, role:parent\ng, role:parent, role:admin"},
		{name: "role cycle", row: "g, role:child, role:admin\ng, role:admin, role:child"},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("LoadPolicy() panicked instead of rejecting the malformed row")
				}
			}()
			content := "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\n" + test.row + "\n"
			policy, err := LoadPolicy(policyFile(t, content), []string{"dev", "prod"})
			if policy != nil || !errors.Is(err, ErrPolicy) {
				t.Fatalf("LoadPolicy() returned a policy or error = %v, want nil and ErrPolicy", err)
			}
		})
	}
}

func TestAuthorizeRotateUsesOnePolicySnapshot(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\n"
	path := policyFile(t, initial)
	authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})

	var rewrite sync.Once
	rewritten := false
	replacePolicyMatcher(t, authorizer, path, func(args ...interface{}) (interface{}, error) {
		rewrite.Do(func() {
			updated := "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, deny\n"
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
	if err := authorizer.AuthorizeRotate(principalWithGroups("admins"), "dev", "prod"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fresh AuthorizeRotate() error = %v, want ErrForbidden after removal", err)
	}
}

func TestEvaluateKeepsDirectAndRotationChecksOnOneSnapshot(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, decrypt, allow\np, role:admin, rotation:dev:prod, rotate, allow\n"
	path := policyFile(t, initial)
	authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})
	actor := principalWithGroups("admins")
	var rewrite sync.Once
	rewritten := false
	replacePolicyMatcher(t, authorizer, path, func(args ...interface{}) (interface{}, error) {
		rewrite.Do(func() {
			replacePolicyFile(t, path, "g, group:admins, role:admin\np, role:admin, profiles, profiles:list, allow\np, role:admin, profile:dev, decrypt, deny\np, role:admin, rotation:dev:prod, rotate, deny\np, role:admin, rotation:prod:dev, rotate, allow\n")
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); !errors.Is(err, ErrForbidden) {
				t.Errorf("removal probe error = %v, want ErrForbidden", err)
			}
			rewritten = true
		})
		resource, _ := args[0].(string)
		selector, _ := args[1].(string)
		return matchesPolicyObject(resource, selector), nil
	})
	checks := []Check{
		{Action: ActionListProfiles, Resource: ResourceProfiles},
		{Action: ActionDecrypt, Resource: ProfileResource("dev")},
		{Action: ActionRotate, Resource: RotationResource("dev", "prod")},
		{Action: ActionRotate, Resource: RotationResource("prod", "dev")},
	}
	got, err := authorizer.Evaluate(actor, checks)
	if want := []bool{true, true, true, false}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("old Evaluate() = %v, %v; want %v after removal probe", got, err, want)
	}
	if !rewritten {
		t.Fatal("policy replacement hook was not exercised")
	}
	got, err = authorizer.Evaluate(actor, checks)
	if want := []bool{true, false, false, true}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh Evaluate() = %v, %v; want %v", got, err, want)
	}
}

func TestAuthorizerRotationReloadFailsClosedAndRecovers(t *testing.T) {
	initial := "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, allow\n"
	for _, test := range []struct {
		name        string
		replacement string
		remove      bool
		wantErr     error
	}{
		{name: "explicit deny", replacement: "g, group:admins, role:admin\np, role:admin, rotation:dev:prod, rotate, deny\n", wantErr: ErrForbidden},
		{name: "no lane with direct rights", replacement: "g, group:admins, role:admin\np, role:admin, profile:dev, decrypt, allow\np, role:admin, profile:prod, encrypt, allow\n", wantErr: ErrForbidden},
		{name: "malformed replacement", replacement: initial + "p, role:admin, rotation:dev:missing, rotate, deny\n", wantErr: ErrPolicy},
		{name: "missing policy", remove: true, wantErr: ErrPolicy},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := policyFile(t, initial)
			authorizer := loadAuthorizer(t, path, []string{"dev", "prod"})
			actor := principalWithGroups("admins")
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); err != nil {
				t.Fatalf("initial AuthorizeRotate() error = %v", err)
			}
			if test.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal("remove synthetic policy failed")
				}
			} else {
				replacePolicyFile(t, path, test.replacement)
			}
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); !errors.Is(err, test.wantErr) {
				t.Fatalf("replaced AuthorizeRotate() error = %v, want %v", err, test.wantErr)
			}
			got, err := authorizer.Evaluate(actor, []Check{{Action: ActionRotate, Resource: RotationResource("dev", "prod")}})
			if errors.Is(test.wantErr, ErrPolicy) {
				if got != nil || !errors.Is(err, ErrPolicy) {
					t.Fatalf("unavailable Evaluate() = %v, %v; want nil, ErrPolicy", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, []bool{false}) {
				t.Fatalf("denied Evaluate() = %v, %v; want [false], nil", got, err)
			}
			if test.remove {
				if err := os.WriteFile(path, []byte(initial+"# recovered\n"), 0o600); err != nil {
					t.Fatal("restore synthetic policy failed")
				}
			} else {
				replacePolicyFile(t, path, initial+"# recovered\n")
			}
			if err := authorizer.AuthorizeRotate(actor, "dev", "prod"); err != nil {
				t.Fatalf("recovered AuthorizeRotate() error = %v", err)
			}
		})
	}
}

func TestAuthorizeReturnsPolicyErrorWhenMatcherFails(t *testing.T) {
	path := policyFile(t, "g, group:admins, role:admin\np, role:admin, profile:dev, encrypt, allow\np, role:admin, rotation:dev:dev, rotate, allow\n")
	authorizer := loadAuthorizer(t, path, []string{"dev"})
	replacePolicyMatcher(t, authorizer, path, func(...interface{}) (interface{}, error) {
		return false, errors.New("matcher failed")
	})
	if err := authorizer.Authorize(principalWithGroups("admins"), ActionEncrypt, ProfileResource("dev")); !errors.Is(err, ErrPolicy) {
		t.Fatalf("Authorize() error = %v, want %v", err, ErrPolicy)
	}
	if err := authorizer.AuthorizeRotate(principalWithGroups("admins"), "dev", "dev"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("AuthorizeRotate() error = %v, want ErrPolicy", err)
	}
	got, err := authorizer.Evaluate(principalWithGroups("admins"), []Check{{Action: ActionRotate, Resource: RotationResource("dev", "dev")}})
	if got != nil || !errors.Is(err, ErrPolicy) {
		t.Fatalf("Evaluate() = %v, %v; want nil, ErrPolicy", got, err)
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
