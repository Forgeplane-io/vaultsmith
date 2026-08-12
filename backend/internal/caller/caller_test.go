package caller

import (
	"reflect"
	"testing"
)

func TestCallerConstructorsCopyAuthority(t *testing.T) {
	groups := []string{"operators"}
	scopes := []string{"vaultsmith.profile.read", "vaultsmith.encrypt", "vaultsmith.encrypt"}

	session, err := NewSession("https://issuer.example", "subject", groups)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	bearer, err := NewBearer("https://issuer.example", "service-account", groups, scopes)
	if err != nil {
		t.Fatalf("NewBearer() error = %v", err)
	}
	groups[0] = "mutated"
	scopes[0] = "mutated"

	if session.Kind() != KindSession || session.Issuer() != "https://issuer.example" || session.Subject() != "subject" {
		t.Fatalf("session caller = %#v", session)
	}
	if got := session.Groups(); !reflect.DeepEqual(got, []string{"operators"}) {
		t.Fatalf("session groups = %#v", got)
	}
	if session.HasScope("vaultsmith.encrypt") {
		t.Fatal("session caller unexpectedly has an OAuth scope")
	}
	if bearer.Kind() != KindBearer || !bearer.HasScope("vaultsmith.profile.read") || !bearer.HasScope("vaultsmith.encrypt") {
		t.Fatalf("bearer caller = %#v", bearer)
	}
	if got := bearer.Scopes(); !reflect.DeepEqual(got, []string{"vaultsmith.encrypt", "vaultsmith.profile.read"}) {
		t.Fatalf("bearer scopes = %#v", got)
	}

	returnedGroups := bearer.Groups()
	returnedGroups[0] = "mutated-again"
	if got := bearer.Groups(); !reflect.DeepEqual(got, []string{"operators"}) {
		t.Fatalf("caller groups were mutable through accessor: %#v", got)
	}
}

func TestAnonymousCallerHasNoIdentityOrAuthority(t *testing.T) {
	anonymous := Anonymous()
	if anonymous.Kind() != KindAnonymous {
		t.Fatalf("kind = %q, want %q", anonymous.Kind(), KindAnonymous)
	}
	if anonymous.Issuer() != "" || anonymous.Subject() != "" || len(anonymous.Groups()) != 0 || len(anonymous.Scopes()) != 0 {
		t.Fatalf("anonymous caller contains identity or authority: %#v", anonymous)
	}
}

func TestAuthenticatedCallerRequiresIssuerAndSubject(t *testing.T) {
	for _, test := range []struct {
		name    string
		issuer  string
		subject string
	}{
		{name: "missing issuer", subject: "subject"},
		{name: "missing subject", issuer: "https://issuer.example"},
		{name: "blank issuer", issuer: "  ", subject: "subject"},
		{name: "blank subject", issuer: "https://issuer.example", subject: "  "},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSession(test.issuer, test.subject, nil); err == nil {
				t.Fatal("NewSession() unexpectedly succeeded")
			}
			if _, err := NewBearer(test.issuer, test.subject, nil, nil); err == nil {
				t.Fatal("NewBearer() unexpectedly succeeded")
			}
		})
	}
}
