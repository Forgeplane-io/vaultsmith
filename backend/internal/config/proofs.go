package config

import (
	"fmt"
	"os"
	"strings"
)

const (
	proofsEnabledEnv     = "PROOFS_ENABLED"
	proofsKeyringFileEnv = "PROOFS_KEYRING_FILE"
)

// LoadProofs loads the transport-independent keyring lifecycle seam. Proofs
// are disabled by default; enabled mode requires the existing canonical HTTPS
// public origin even when authentication is off.
func LoadProofs(lookup EnvLookup) (ProofsConfig, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	enabled := false
	if raw, ok := lookup(proofsEnabledEnv); ok && strings.TrimSpace(raw) != "" {
		parsed, err := boolOption(proofsEnabledEnv, raw)
		if err != nil {
			return ProofsConfig{}, err
		}
		enabled = parsed
	}
	if !enabled {
		return ProofsConfig{}, nil
	}

	keyringFile, err := requiredValue(lookup, proofsKeyringFileEnv)
	if err != nil {
		return ProofsConfig{}, err
	}
	publicBase, err := requiredValue(lookup, "PUBLIC_BASE_URL")
	if err != nil {
		return ProofsConfig{}, err
	}
	origin, err := validateResourceOrigin("PUBLIC_BASE_URL", publicBase)
	if err != nil {
		return ProofsConfig{}, fmt.Errorf("proofs require a valid PUBLIC_BASE_URL: %w", err)
	}
	return ProofsConfig{
		Enabled:     true,
		KeyringFile: keyringFile,
		Issuer:      canonicalOrigin(origin),
	}, nil
}
