package httpapi

import (
	"fmt"
	"log"
	"net/http"

	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

const admissionBenchmarkReceipt = "docs/benchmarks/admission-linux-amd64-2026-08-12.md"

func writeAdmissionSaturated(w http.ResponseWriter, admission *vaultservice.Admission) {
	writeOperationAdmissionSaturated(w, admission, true)
}

// Generate is randomized and explicitly non-idempotent. Its saturation
// response must not invite an automatic retry.
func writeGenerateAdmissionSaturated(w http.ResponseWriter, admission *vaultservice.Admission) {
	writeOperationAdmissionSaturated(w, admission, false)
}

func writeOperationAdmissionSaturated(w http.ResponseWriter, admission *vaultservice.Admission, retryable bool) {
	if shouldLogAdmissionSaturation(admission.Rejections()) {
		log.Print(operationAdmissionSaturationLogLine(admission, retryable))
	}
	if retryable {
		w.Header().Set("Retry-After", "1")
	}
	writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
}

func admissionSaturationLogLine(admission *vaultservice.Admission) string {
	return operationAdmissionSaturationLogLine(admission, true)
}

func operationAdmissionSaturationLogLine(admission *vaultservice.Admission, retryable bool) string {
	if !retryable {
		return fmt.Sprintf(
			"vault operation admission saturated compiled_capacity_budget=%d configured_capacity=%d observed_in_use=%d saturation_count=%d remediation=%s",
			vaultservice.MaxRuntimeAdmissionCapacity,
			admission.Capacity(),
			admission.InUse(),
			admission.Rejections(),
			admissionBenchmarkReceipt,
		)
	}
	return fmt.Sprintf(
		"vault operation admission saturated compiled_capacity_budget=%d configured_capacity=%d observed_in_use=%d saturation_count=%d retry_after_seconds=1 remediation=%s",
		vaultservice.MaxRuntimeAdmissionCapacity,
		admission.Capacity(),
		admission.InUse(),
		admission.Rejections(),
		admissionBenchmarkReceipt,
	)
}

// Logging at powers of two preserves the first event and gives an unbounded,
// logarithmic pressure signal without emitting one line per rejected request.
func shouldLogAdmissionSaturation(count uint64) bool {
	return count != 0 && count&(count-1) == 0
}
