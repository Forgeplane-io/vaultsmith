package httpapi

import (
	"strings"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

func TestAdmissionSaturationLogLineNamesEveryOperationalBudget(t *testing.T) {
	admission, err := vaultservice.NewAdmission(7)
	if err != nil {
		t.Fatal(err)
	}
	line := admissionSaturationLogLine(admission)
	for _, required := range []string{
		"compiled_capacity_budget=16",
		"configured_capacity=7",
		"observed_in_use=0",
		"saturation_count=0",
		"retry_after_seconds=1",
		"remediation=docs/benchmarks/admission-linux-amd64-2026-08-12.md",
	} {
		if !strings.Contains(line, required) {
			t.Fatalf("log line %q does not contain %q", line, required)
		}
	}
}

func TestAdmissionSaturationLogCadenceIsExponentiallyBounded(t *testing.T) {
	for _, count := range []uint64{1, 2, 4, 8, 1024} {
		if !shouldLogAdmissionSaturation(count) {
			t.Fatalf("count %d was not logged", count)
		}
	}
	for _, count := range []uint64{0, 3, 5, 7, 1023} {
		if shouldLogAdmissionSaturation(count) {
			t.Fatalf("count %d was logged", count)
		}
	}
}
