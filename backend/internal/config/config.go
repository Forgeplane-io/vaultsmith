package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
)

const profilesEnv = "VAULT_PROFILES_JSON"

var (
	ErrProfileNotFound = errors.New("profile not found")
	profileIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	passwordEnvPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	reservedEnvNames   = map[string]struct{}{
		profilesEnv:   {},
		"HTTP_ADDR":   {},
		"MCP_ENABLED": {},
		"MCPGODEBUG":  {},
	}
)

type PublicProfile struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type rawProfile struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	PasswordEnv string `json:"passwordEnv"`
}

type profile struct {
	public   PublicProfile
	password []byte
}

type Config struct {
	profiles []profile
	executor *executor
	auth     AuthConfig
	mcp      MCPConfig
}

type MCPConfig struct {
	Enabled bool
}

type ProfileExecutor interface {
	Encrypt(context.Context, string) (string, error)
	Decrypt(context.Context, string) (string, error)
}

type Executor interface {
	ForProfile(string) (ProfileExecutor, error)
}

type executor struct {
	profiles map[string]*profileExecutor
}

type profileExecutor struct {
	profile profile
}

// LoadFromEnv loads the non-secret profile metadata from VAULT_PROFILES_JSON
// and resolves each passwordEnv reference through the process environment.
func LoadFromEnv() (*Config, error) {
	profilesJSON, ok := os.LookupEnv(profilesEnv)
	if !ok || strings.TrimSpace(profilesJSON) == "" {
		return nil, fmt.Errorf("%s is required", profilesEnv)
	}
	return LoadJSON(profilesJSON, os.LookupEnv)
}

func LoadApplicationFromEnv() (*Config, error) {
	if err := RejectMCPGoDebug(os.LookupEnv); err != nil {
		return nil, err
	}
	loaded, err := LoadFromEnv()
	if err != nil {
		return nil, err
	}
	auth, err := LoadAuth(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	mcpEnabled, err := LoadMCPEnabled(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	loaded.auth = *auth
	loaded.mcp = MCPConfig{Enabled: mcpEnabled}
	return loaded, nil
}

// LoadJSON validates profile metadata and resolves passwords through lookup.
// The password values are retained only inside the returned Config.
func LoadJSON(profilesJSON string, lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	decoder := json.NewDecoder(strings.NewReader(profilesJSON))
	decoder.DisallowUnknownFields()
	var rawProfiles []rawProfile
	if err := decoder.Decode(&rawProfiles); err != nil {
		return nil, fmt.Errorf("invalid %s JSON", profilesEnv)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("invalid %s JSON", profilesEnv)
	}
	if len(rawProfiles) == 0 {
		return nil, errors.New("at least one vault profile is required")
	}

	profiles := make([]profile, 0, len(rawProfiles))
	seenIDs := make(map[string]struct{}, len(rawProfiles))
	seenPasswordEnvs := make(map[string]struct{}, len(rawProfiles))
	for index, raw := range rawProfiles {
		if !profileIDPattern.MatchString(raw.ID) {
			return nil, fmt.Errorf("profile %d has invalid id", index)
		}
		if _, exists := seenIDs[raw.ID]; exists {
			return nil, fmt.Errorf("duplicate profile id %q", raw.ID)
		}
		seenIDs[raw.ID] = struct{}{}

		label := strings.TrimSpace(raw.Label)
		if label == "" {
			return nil, fmt.Errorf("profile %q has an empty label", raw.ID)
		}
		if !passwordEnvPattern.MatchString(raw.PasswordEnv) {
			return nil, fmt.Errorf("profile %q has an invalid password environment name", raw.ID)
		}
		if _, reserved := reservedEnvNames[raw.PasswordEnv]; reserved {
			return nil, fmt.Errorf("profile %q uses a reserved password environment name", raw.ID)
		}
		if _, exists := seenPasswordEnvs[raw.PasswordEnv]; exists {
			return nil, fmt.Errorf("password environment name %q is used more than once", raw.PasswordEnv)
		}
		seenPasswordEnvs[raw.PasswordEnv] = struct{}{}

		password, ok := lookup(raw.PasswordEnv)
		if !ok || password == "" {
			return nil, fmt.Errorf("profile %q references a missing or empty password environment", raw.ID)
		}
		profiles = append(profiles, profile{
			public:   PublicProfile{ID: raw.ID, Label: label},
			password: []byte(password),
		})
	}

	byID := make(map[string]*profileExecutor, len(profiles))
	for _, current := range profiles {
		byID[current.public.ID] = &profileExecutor{profile: current}
	}
	return &Config{profiles: profiles, executor: &executor{profiles: byID}}, nil
}

func IsValidProfileID(id string) bool {
	return profileIDPattern.MatchString(id)
}

func (c *Config) PublicProfiles() []PublicProfile {
	public := make([]PublicProfile, 0, len(c.profiles))
	for _, current := range c.profiles {
		public = append(public, current.public)
	}
	return public
}

func (c *Config) Auth() AuthConfig {
	return c.auth
}

func (c *Config) MCP() MCPConfig {
	return c.mcp
}

func (c *Config) Executor() Executor {
	return c.executor
}

func (e *executor) ForProfile(profileID string) (ProfileExecutor, error) {
	current, ok := e.profiles[profileID]
	if !ok {
		return nil, ErrProfileNotFound
	}
	return current, nil
}

func (e *profileExecutor) Encrypt(ctx context.Context, value string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	output, err := ansiblevault.Encrypt([]byte(value), e.profile.password, e.profile.public.ID)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return output, nil
}

func (e *profileExecutor) Decrypt(ctx context.Context, value string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	plaintext, err := ansiblevault.Decrypt(value, e.profile.password)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return string(plaintext), nil
}
