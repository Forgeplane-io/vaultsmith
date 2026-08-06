package authz

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

//go:embed model.conf
var embeddedModel string

const (
	ActionListProfiles = "profiles:list"
	ActionEncrypt      = "encrypt"
	ActionDecrypt      = "decrypt"

	ResourceProfiles = "profiles"
)

var (
	ErrForbidden = errors.New("authorization denied")
	ErrPolicy    = errors.New("authorization policy unavailable")
)

type Rule struct {
	Subject string
	Object  string
	Action  string
	Effect  string
}

type Policy struct {
	enforcer   *casbin.Enforcer
	rules      []Rule
	groupRoles map[string][]string
	parents    map[string]string
	path       string
	profileIDs []string
	modTime    time.Time
	size       int64
}

type Authorizer struct {
	mu     sync.RWMutex
	policy *Policy
}

func LoadPolicy(path string, profileIDs []string) (*Policy, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: policy file is required", ErrPolicy)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: policy file unavailable", ErrPolicy)
	}
	m, err := model.NewModelFromString(embeddedModel)
	if err != nil {
		return nil, fmt.Errorf("%w: embedded model invalid", ErrPolicy)
	}
	enforcer, err := casbin.NewEnforcer(m, fileadapter.NewAdapter(path))
	if err != nil {
		return nil, fmt.Errorf("%w: policy adapter unavailable", ErrPolicy)
	}
	enforcer.AddFunction("vaultsmithMatch", func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return false, fmt.Errorf("invalid resource matcher arguments")
		}
		resource, resourceOK := args[0].(string)
		selector, selectorOK := args[1].(string)
		if !resourceOK || !selectorOK {
			return false, fmt.Errorf("invalid resource matcher values")
		}
		return matchesPolicyObject(resource, selector), nil
	})
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("%w: policy load failed", ErrPolicy)
	}
	policy := &Policy{
		enforcer:   enforcer,
		groupRoles: make(map[string][]string),
		parents:    make(map[string]string),
		path:       path,
		profileIDs: append([]string(nil), profileIDs...),
		modTime:    fileInfo.ModTime(),
		size:       fileInfo.Size(),
	}
	permissionRows, err := enforcer.GetPolicy()
	if err != nil {
		return nil, fmt.Errorf("%w: permission policy unavailable", ErrPolicy)
	}
	for _, row := range permissionRows {
		if len(row) != 4 {
			return nil, fmt.Errorf("%w: malformed permission row", ErrPolicy)
		}
		policy.rules = append(policy.rules, Rule{Subject: row[0], Object: row[1], Action: row[2], Effect: row[3]})
	}
	groupingRows, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return nil, fmt.Errorf("%w: grouping policy unavailable", ErrPolicy)
	}
	for _, row := range groupingRows {
		if len(row) != 2 {
			return nil, fmt.Errorf("%w: malformed role row", ErrPolicy)
		}
		if strings.HasPrefix(row[0], "group:") && strings.HasPrefix(row[1], "role:") {
			policy.groupRoles[row[0]] = append(policy.groupRoles[row[0]], row[1])
			continue
		}
		if strings.HasPrefix(row[0], "role:") && strings.HasPrefix(row[1], "role:") {
			if _, exists := policy.parents[row[0]]; exists {
				return nil, fmt.Errorf("%w: multiple parents for role", ErrPolicy)
			}
			policy.parents[row[0]] = row[1]
			continue
		}
		return nil, fmt.Errorf("%w: invalid role mapping", ErrPolicy)
	}
	if err := validatePolicy(policy, profileIDs); err != nil {
		return nil, err
	}
	return policy, nil
}

func NewAuthorizer(policy *Policy) (*Authorizer, error) {
	if policy == nil || policy.enforcer == nil {
		return nil, fmt.Errorf("%w: policy is nil", ErrPolicy)
	}
	return &Authorizer{policy: policy}, nil
}

func (a *Authorizer) currentPolicy() (*Policy, error) {
	if a == nil {
		return nil, ErrPolicy
	}
	a.mu.RLock()
	policy := a.policy
	a.mu.RUnlock()
	if policy == nil || policy.enforcer == nil {
		return nil, ErrPolicy
	}
	if policy.path == "" {
		return policy, nil
	}
	fileInfo, err := os.Stat(policy.path)
	if err != nil {
		return nil, fmt.Errorf("%w: policy file unavailable", ErrPolicy)
	}
	if fileInfo.ModTime().Equal(policy.modTime) && fileInfo.Size() == policy.size {
		return policy, nil
	}
	reloaded, err := LoadPolicy(policy.path, policy.profileIDs)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.policy = reloaded
	a.mu.Unlock()
	return reloaded, nil
}

func (a *Authorizer) Authorize(principal authn.Principal, action, resource string) error {
	policy, err := a.currentPolicy()
	if err != nil {
		return err
	}
	return authorizeWithPolicy(policy, principal, action, resource)
}

func authorizeWithPolicy(policy *Policy, principal authn.Principal, action, resource string) error {
	if policy == nil || policy.enforcer == nil {
		return ErrPolicy
	}
	roles := policy.rolesForGroups(principal.Groups)
	if len(roles) == 0 {
		return ErrForbidden
	}
	allow, deny, err := policy.evaluate(roles, resource, action)
	if err != nil {
		return err
	}
	if deny || !allow {
		return ErrForbidden
	}
	return nil
}

func (a *Authorizer) FilterProfiles(principal authn.Principal, profileIDs []string) []string {
	policy, err := a.currentPolicy()
	if err != nil || authorizeWithPolicy(policy, principal, ActionListProfiles, ResourceProfiles) != nil {
		return nil
	}
	filtered := make([]string, 0, len(profileIDs))
	for _, profileID := range profileIDs {
		resource := ProfileResource(profileID)
		if authorizeWithPolicy(policy, principal, ActionEncrypt, resource) == nil || authorizeWithPolicy(policy, principal, ActionDecrypt, resource) == nil {
			filtered = append(filtered, profileID)
		}
	}
	return filtered
}

func (a *Authorizer) AuthorizeRotate(principal authn.Principal, sourceProfileID, destinationProfileID string) error {
	policy, err := a.currentPolicy()
	if err != nil {
		return err
	}
	if err := authorizeWithPolicy(policy, principal, ActionDecrypt, ProfileResource(sourceProfileID)); err != nil {
		return err
	}
	return authorizeWithPolicy(policy, principal, ActionEncrypt, ProfileResource(destinationProfileID))
}

func ProfileResource(profileID string) string {
	return "profile:" + profileID
}

func (p *Policy) rolesForGroups(groups []string) []string {
	seen := make(map[string]struct{})
	var roles []string
	for _, group := range groups {
		for _, role := range p.groupRoles["group:"+group] {
			for current := role; current != ""; current = p.parents[current] {
				if _, exists := seen[current]; exists {
					break
				}
				seen[current] = struct{}{}
				roles = append(roles, current)
			}
		}
	}
	sort.Strings(roles)
	return roles
}

func (p *Policy) evaluate(roles []string, object, action string) (allow, deny bool, err error) {
	roleSet := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		roleSet[role] = struct{}{}
		ok, enforceErr := p.enforcer.Enforce(role, object, action)
		if enforceErr != nil {
			return false, false, fmt.Errorf("%w: policy enforcement failed", ErrPolicy)
		}
		if ok {
			allow = true
		}
	}
	for _, rule := range p.rules {
		if _, exists := roleSet[rule.Subject]; !exists || rule.Action != action || !matchesPolicyObject(object, rule.Object) {
			continue
		}
		switch rule.Effect {
		case "allow":
			allow = true
		case "deny":
			deny = true
		}
	}
	return allow, deny, nil
}

func validatePolicy(policy *Policy, profileIDs []string) error {
	profiles := make(map[string]struct{}, len(profileIDs))
	for _, id := range profileIDs {
		if !config.IsValidProfileID(id) {
			return fmt.Errorf("%w: invalid configured profile id", ErrPolicy)
		}
		profiles[id] = struct{}{}
	}
	seenRules := make(map[string]struct{})
	for _, rule := range policy.rules {
		if !strings.HasPrefix(rule.Subject, "role:") || rule.Subject == "role:" {
			return fmt.Errorf("%w: permission subject must be a role", ErrPolicy)
		}
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("%w: invalid permission effect", ErrPolicy)
		}
		if rule.Action != ActionListProfiles && rule.Action != ActionEncrypt && rule.Action != ActionDecrypt {
			return fmt.Errorf("%w: invalid permission action", ErrPolicy)
		}
		key := strings.Join([]string{rule.Subject, rule.Object, rule.Action, rule.Effect}, "\x00")
		if _, exists := seenRules[key]; exists {
			return fmt.Errorf("%w: duplicate permission row", ErrPolicy)
		}
		seenRules[key] = struct{}{}
		if err := validateObject(rule.Object, rule.Action, profiles); err != nil {
			return err
		}
	}
	for role := range policy.parents {
		seen := map[string]bool{}
		for current, depth := role, 0; current != ""; current, depth = policy.parents[current], depth+1 {
			if seen[current] {
				return fmt.Errorf("%w: role inheritance cycle", ErrPolicy)
			}
			seen[current] = true
			if depth > 1 {
				return fmt.Errorf("%w: role inheritance exceeds one level", ErrPolicy)
			}
		}
	}
	knownRoles := make(map[string]struct{})
	for _, rule := range policy.rules {
		knownRoles[rule.Subject] = struct{}{}
	}
	for child, parent := range policy.parents {
		knownRoles[child] = struct{}{}
		knownRoles[parent] = struct{}{}
	}
	for _, roles := range policy.groupRoles {
		for _, role := range roles {
			if _, ok := knownRoles[role]; !ok {
				return fmt.Errorf("%w: group references unknown role", ErrPolicy)
			}
		}
	}
	return nil
}

func matchesPolicyObject(resource, selector string) bool {
	if strings.HasSuffix(selector, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(selector, "*"))
	}
	return resource == selector
}

func validateObject(object, action string, profiles map[string]struct{}) error {
	if object == ResourceProfiles {
		if action != ActionListProfiles {
			return fmt.Errorf("%w: global resource only supports profiles:list", ErrPolicy)
		}
		return nil
	}
	if !strings.HasPrefix(object, "profile:") || action == ActionListProfiles {
		return fmt.Errorf("%w: invalid policy resource", ErrPolicy)
	}
	selector := strings.TrimPrefix(object, "profile:")
	if strings.Count(selector, "*") > 1 || strings.Contains(selector, "*") && !strings.HasSuffix(selector, "*") {
		return fmt.Errorf("%w: invalid profile selector", ErrPolicy)
	}
	if strings.HasSuffix(selector, "*") {
		prefix := strings.TrimSuffix(selector, "*")
		if !config.IsValidProfileID(prefix) {
			return fmt.Errorf("%w: invalid profile prefix selector", ErrPolicy)
		}
		matched := false
		for id := range profiles {
			if strings.HasPrefix(id, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: profile selector matches no configured profile", ErrPolicy)
		}
		return nil
	}
	if _, ok := profiles[selector]; !ok || !config.IsValidProfileID(selector) {
		return fmt.Errorf("%w: policy references unknown profile", ErrPolicy)
	}
	return nil
}
