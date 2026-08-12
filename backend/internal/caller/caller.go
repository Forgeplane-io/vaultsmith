package caller

import (
	"errors"
	"sort"
	"strings"
)

// Kind identifies how Vaultsmith authenticated a request.
type Kind string

const (
	KindSession   Kind = "session"
	KindBearer    Kind = "bearer"
	KindAnonymous Kind = "anonymous"
)

var ErrInvalidCaller = errors.New("invalid caller")

// Caller contains only verified identity and authority used by the application
// service. It deliberately excludes browser-session and token transport state.
type Caller struct {
	kind    Kind
	issuer  string
	subject string
	groups  []string
	scopes  map[string]struct{}
}

func NewSession(issuer, subject string, groups []string) (Caller, error) {
	return newAuthenticated(KindSession, issuer, subject, groups, nil)
}

func NewBearer(issuer, subject string, groups, scopes []string) (Caller, error) {
	return newAuthenticated(KindBearer, issuer, subject, groups, scopes)
}

func Anonymous() Caller {
	return Caller{kind: KindAnonymous}
}

func newAuthenticated(kind Kind, issuer, subject string, groups, scopes []string) (Caller, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" {
		return Caller{}, ErrInvalidCaller
	}
	copiedGroups := append([]string(nil), groups...)
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	return Caller{
		kind:    kind,
		issuer:  issuer,
		subject: subject,
		groups:  copiedGroups,
		scopes:  scopeSet,
	}, nil
}

func (c Caller) Kind() Kind {
	return c.kind
}

func (c Caller) Issuer() string {
	return c.issuer
}

func (c Caller) Subject() string {
	return c.subject
}

func (c Caller) Groups() []string {
	return append([]string(nil), c.groups...)
}

func (c Caller) HasScope(scope string) bool {
	_, ok := c.scopes[scope]
	return ok
}

func (c Caller) Scopes() []string {
	scopes := make([]string, 0, len(c.scopes))
	for scope := range c.scopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}
