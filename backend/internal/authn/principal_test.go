package authn

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPrincipalFromVerifiedClaims(t *testing.T) {
	principal, err := principalFromClaims("https://issuer.example", map[string]any{
		"sub":            "user-123",
		"email":          "user@example.test",
		"email_verified": true,
		"groups":         []any{"vault-admins", "vault-readers"},
	}, "groups", time.Unix(100, 0), time.Unix(200, 0))
	if err != nil {
		t.Fatalf("principalFromClaims() error = %v", err)
	}
	if principal.Issuer != "https://issuer.example" || principal.Subject != "user-123" {
		t.Fatalf("unexpected identity: %+v", principal)
	}
	if !principal.EmailVerified || principal.Email != "user@example.test" {
		t.Fatalf("unexpected verified email: %+v", principal)
	}
	if !reflect.DeepEqual(principal.Groups, []string{"vault-admins", "vault-readers"}) {
		t.Fatalf("groups = %#v", principal.Groups)
	}
}

func TestPrincipalFromClaimsDropsUnverifiedEmail(t *testing.T) {
	principal, err := principalFromClaims("issuer", map[string]any{
		"sub":            "user-123",
		"email":          "user@example.test",
		"email_verified": false,
		"groups":         []any{},
	}, "groups", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("principalFromClaims() error = %v", err)
	}
	if principal.Email != "" || principal.EmailVerified {
		t.Fatalf("unverified email was retained: %+v", principal)
	}
}

func TestPrincipalFromClaimsTreatsMissingGroupsAsNoPermissions(t *testing.T) {
	principal, err := principalFromClaims("issuer", map[string]any{"sub": "user-123"}, "groups", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("principalFromClaims() error = %v", err)
	}
	if !reflect.DeepEqual(principal.Groups, []string{}) {
		t.Fatalf("groups = %#v, want empty group set", principal.Groups)
	}
}

func TestPrincipalFromClaimsRejectsMalformedGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups any
		want   string
	}{
		{name: "wrong type", groups: "vault-admins", want: "groups claim"},
		{name: "wrong member type", groups: []any{"vault-admins", 1}, want: "groups claim"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{"sub": "user-123"}
			if tt.groups != nil {
				claims["groups"] = tt.groups
			}
			_, err := principalFromClaims("issuer", claims, "groups", time.Time{}, time.Time{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("principalFromClaims() error = %v, want mention %q", err, tt.want)
			}
		})
	}
}

func TestPrincipalFromClaimsSupportsNestedGroupPath(t *testing.T) {
	principal, err := principalFromClaims("issuer", map[string]any{
		"sub": "user-123",
		"realm": map[string]any{
			"groups": []any{"vault-admins"},
		},
	}, "realm.groups", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("principalFromClaims() error = %v", err)
	}
	if !reflect.DeepEqual(principal.Groups, []string{"vault-admins"}) {
		t.Fatalf("groups = %#v", principal.Groups)
	}
}
