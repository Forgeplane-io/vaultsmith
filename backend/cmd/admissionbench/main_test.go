package main

import (
	"net/http"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/httpapi"
)

func TestValidateBenchmarkEnvironment(t *testing.T) {
	tests := []struct {
		name                string
		release             bool
		goos                string
		goarch              string
		containerLimit      int64
		containerLimitKnown bool
		wantError           bool
	}{
		{name: "development without cgroup", goos: "darwin", goarch: "arm64"},
		{name: "development rejects lower memory", goos: "linux", goarch: "amd64", containerLimit: releaseMinimumPodMemoryBytes - 1, containerLimitKnown: true, wantError: true},
		{name: "qualified release", release: true, goos: "linux", goarch: "amd64", containerLimit: releaseMinimumPodMemoryBytes, containerLimitKnown: true},
		{name: "release rejects architecture", release: true, goos: "linux", goarch: "arm64", containerLimit: releaseMinimumPodMemoryBytes, containerLimitKnown: true, wantError: true},
		{name: "release rejects unknown cgroup", release: true, goos: "linux", goarch: "amd64", wantError: true},
		{name: "release rejects different cgroup", release: true, goos: "linux", goarch: "amd64", containerLimit: releaseMinimumPodMemoryBytes * 2, containerLimitKnown: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateBenchmarkEnvironment(test.release, test.goos, test.goarch, test.containerLimit, test.containerLimitKnown)
			if (err != nil) != test.wantError {
				t.Fatalf("validateBenchmarkEnvironment() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestBenchmarkFixtureCoversReleaseWorkloads(t *testing.T) {
	fixture, err := newBenchmarkFixture(2)
	if err != nil {
		t.Fatalf("newBenchmarkFixture() error = %v", err)
	}
	defer fixture.Close()

	transports := map[string]bool{}
	authenticationKinds := map[string]bool{}
	operationsByTransport := map[string]map[string]bool{}
	malformedAtLimit := map[string]bool{}
	for _, item := range fixture.workload {
		transports[item.Transport] = true
		authenticationKinds[item.AuthenticationKind] = true
		if operationsByTransport[item.Transport] == nil {
			operationsByTransport[item.Transport] = map[string]bool{}
		}
		operationsByTransport[item.Transport][item.Operation] = true
		if item.Operation == "decode_rejection" {
			if item.RequestBodyBytes != httpapi.MaxRequestBodyBytes {
				t.Errorf("workload %q body bytes = %d, want %d", item.Name, item.RequestBodyBytes, httpapi.MaxRequestBodyBytes)
			}
			if item.ExpectedStatus != http.StatusBadRequest {
				t.Errorf("workload %q status = %d, want %d", item.Name, item.ExpectedStatus, http.StatusBadRequest)
			}
			malformedAtLimit[item.Transport] = true
		}
	}

	for _, transport := range []string{"canonical_rest", "legacy_rest", "mcp"} {
		if !transports[transport] {
			t.Errorf("missing transport %q", transport)
		}
		for _, operation := range []string{"encrypt", "decrypt", "rotate"} {
			if !operationsByTransport[transport][operation] {
				t.Errorf("transport %q missing operation %q", transport, operation)
			}
		}
	}
	for _, authenticationKind := range []string{"session", "bearer_delegated_user", "bearer_client_credentials", "anonymous"} {
		if !authenticationKinds[authenticationKind] {
			t.Errorf("missing authentication kind %q", authenticationKind)
		}
	}
	for _, transport := range []string{"canonical_rest", "mcp"} {
		if !malformedAtLimit[transport] {
			t.Errorf("missing malformed body-at-limit workload for %q", transport)
		}
	}
}
