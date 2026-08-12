package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const mcpGoDebugHelperEnv = "VAULTSMITH_TEST_MCPGODEBUG_HELPER"

func TestMCPGoDebugStartupFenceInSubprocess(t *testing.T) {
	tests := []struct {
		name       string
		value      *string
		wantError  bool
		wantOutput string
	}{
		{name: "unset", wantOutput: "VAULT_PROFILES_JSON is required"},
		{name: "empty", value: stringPointer(""), wantOutput: "VAULT_PROFILES_JSON is required"},
		{name: "compatibility override", value: stringPointer("allowsessionsinstateless=1"), wantError: true, wantOutput: "MCPGODEBUG must be unset or empty"},
		{name: "other non-empty", value: stringPointer("synthetic=1"), wantError: true, wantOutput: "MCPGODEBUG must be unset or empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=TestMCPGoDebugStartupFenceHelper$")
			command.Env = cleanHelperEnvironment(os.Environ(), test.value)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("helper unexpectedly succeeded: %s", output)
			}
			if !strings.Contains(string(output), test.wantOutput) {
				t.Fatalf("output = %q, want %q", output, test.wantOutput)
			}
			if !test.wantError && strings.Contains(string(output), "MCPGODEBUG must be unset or empty") {
				t.Fatalf("unset/empty MCPGODEBUG hit compatibility guard: %s", output)
			}
		})
	}
}

func TestMCPGoDebugStartupFenceHelper(t *testing.T) {
	if os.Getenv(mcpGoDebugHelperEnv) != "1" {
		return
	}
	if err := run(); err != nil {
		// The helper imports go-sdk before run. Calling run therefore proves that
		// Vaultsmith checks the process variable after SDK initialization and
		// before configuration can reach listener binding.
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(23)
	}
	os.Exit(0)
}

func cleanHelperEnvironment(source []string, mcpGoDebug *string) []string {
	drop := map[string]struct{}{
		mcpGoDebugHelperEnv:   {},
		"MCPGODEBUG":          {},
		"VAULT_PROFILES_JSON": {},
	}
	clean := make([]string, 0, len(source)+2)
	for _, item := range source {
		name, _, _ := strings.Cut(item, "=")
		if _, remove := drop[name]; !remove {
			clean = append(clean, item)
		}
	}
	clean = append(clean, mcpGoDebugHelperEnv+"=1")
	if mcpGoDebug != nil {
		clean = append(clean, "MCPGODEBUG="+*mcpGoDebug)
	}
	return clean
}

func stringPointer(value string) *string { return &value }
