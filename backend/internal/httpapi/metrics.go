package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

type statusRecordingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusRecordingResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecordingResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecordingResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func metricOperationForRequest(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	switch r.URL.Path {
	case "/api/v1/operations":
		return "legacy"
	case "/api/v1/rotations":
		return "rotate"
	case "/api/v1/attestations/verify":
		return "verify"
	}
	_, operation, ok, _ := canonicalProfileOperation(r.URL)
	if !ok {
		return ""
	}
	return string(operation)
}

// metricsRegistry is deliberately small and closed over a fixed vocabulary.
// User-controlled identifiers never become metric labels.
type metricsRegistry struct {
	mu sync.Mutex

	operationRequests  map[string]map[string]uint64
	operationDurations map[string]*durationMetric
	attestationIssued  map[string]uint64
	attestationVerify  map[string]uint64
}

type durationMetric struct {
	buckets [7]uint64
	count   uint64
	sum     float64
}

var (
	metricOperations    = []string{"encrypt", "decrypt", "rotate", "legacy", "verify"}
	metricOutcomes      = []string{"success", "invalid_request", "unauthorized", "forbidden", "not_found", "unavailable", "busy", "failed"}
	attestationOutcomes = []string{"success", "invalid", "feature_unavailable", "unavailable", "busy", "failed"}
	metricBuckets       = []float64{0.005, 0.025, 0.1, 0.5, 1, 5}
)

func newMetricsRegistry() *metricsRegistry {
	registry := &metricsRegistry{
		operationRequests:  make(map[string]map[string]uint64, len(metricOperations)),
		operationDurations: make(map[string]*durationMetric, len(metricOperations)),
		attestationIssued:  make(map[string]uint64, len(attestationOutcomes)),
		attestationVerify:  make(map[string]uint64, len(attestationOutcomes)),
	}
	for _, operation := range metricOperations {
		registry.operationRequests[operation] = make(map[string]uint64, len(metricOutcomes))
		registry.operationDurations[operation] = &durationMetric{}
		for _, outcome := range metricOutcomes {
			registry.operationRequests[operation][outcome] = 0
		}
	}
	for _, outcome := range attestationOutcomes {
		registry.attestationIssued[outcome] = 0
		registry.attestationVerify[outcome] = 0
	}
	return registry
}

func (m *metricsRegistry) observeOperation(operation string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	operation = boundedOperation(operation)
	outcome := outcomeForStatus(status)
	m.mu.Lock()
	m.operationRequests[operation][outcome]++
	metric := m.operationDurations[operation]
	seconds := duration.Seconds()
	metric.count++
	metric.sum += seconds
	for index, upperBound := range metricBuckets {
		if seconds <= upperBound {
			for bucket := index; bucket < len(metric.buckets); bucket++ {
				metric.buckets[bucket]++
			}
			break
		}
	}
	if seconds > metricBuckets[len(metricBuckets)-1] {
		metric.buckets[len(metricBuckets)]++
	}
	m.mu.Unlock()
}

func (m *metricsRegistry) observeAttestationIssued(outcome string) {
	m.observeAttestation(m.attestationIssued, outcome)
}

func (m *metricsRegistry) observeAttestationVerify(outcome string) {
	m.observeAttestation(m.attestationVerify, outcome)
}

func (m *metricsRegistry) observeAttestation(values map[string]uint64, outcome string) {
	if m == nil {
		return
	}
	if !containsAttestationOutcome(outcome) {
		outcome = "failed"
	}
	m.mu.Lock()
	values[outcome]++
	m.mu.Unlock()
}

func boundedOperation(operation string) string {
	for _, candidate := range metricOperations {
		if operation == candidate {
			return candidate
		}
	}
	return "legacy"
}

func containsAttestationOutcome(outcome string) bool {
	for _, candidate := range attestationOutcomes {
		if outcome == candidate {
			return true
		}
	}
	return false
}

func outcomeForStatus(status int) string {
	switch {
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return "success"
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnsupportedMediaType:
		return "invalid_request"
	case status == http.StatusUnauthorized:
		return "unauthorized"
	case status == http.StatusForbidden:
		return "forbidden"
	case status == http.StatusNotFound:
		return "not_found"
	case status == http.StatusTooManyRequests:
		return "busy"
	case status >= http.StatusInternalServerError || status == http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return "failed"
	}
}

func (m *metricsRegistry) write(w http.ResponseWriter, service *vaultservice.Service) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprintln(w, "# TYPE vaultsmith_operation_requests_total counter")
	for _, operation := range metricOperations {
		for _, outcome := range metricOutcomes {
			fmt.Fprintf(w, "vaultsmith_operation_requests_total{operation=%q,outcome=%q} %d\n", operation, outcome, m.operationRequests[operation][outcome])
		}
	}

	fmt.Fprintln(w, "# TYPE vaultsmith_operation_duration_seconds histogram")
	for _, operation := range metricOperations {
		metric := m.operationDurations[operation]
		for index, upperBound := range metricBuckets {
			label := strconv.FormatFloat(upperBound, 'f', -1, 64)
			fmt.Fprintf(w, "vaultsmith_operation_duration_seconds_bucket{operation=%q,le=%q} %d\n", operation, label, metric.buckets[index])
		}
		fmt.Fprintf(w, "vaultsmith_operation_duration_seconds_bucket{operation=%q,le=\"+Inf\"} %d\n", operation, metric.buckets[len(metricBuckets)])
		fmt.Fprintf(w, "vaultsmith_operation_duration_seconds_sum{operation=%q} %s\n", operation, strconv.FormatFloat(metric.sum, 'f', -1, 64))
		fmt.Fprintf(w, "vaultsmith_operation_duration_seconds_count{operation=%q} %d\n", operation, metric.count)
	}

	writeOutcomeCounter(w, "vaultsmith_attestation_issued_total", m.attestationIssued, attestationOutcomes)
	writeOutcomeCounter(w, "vaultsmith_attestation_verify_total", m.attestationVerify, attestationOutcomes)

	var reloadSuccesses, reloadFailures uint64
	loaded := uint64(0)
	if service != nil {
		if manager := service.AttestationManager(); manager != nil {
			if manager.Ready() {
				loaded = 1
			}
			if counters, ok := manager.(interface {
				ReloadSuccessCount() uint64
				ReloadFailureCount() uint64
			}); ok {
				reloadSuccesses = counters.ReloadSuccessCount()
				reloadFailures = counters.ReloadFailureCount()
			}
		}
	}
	fmt.Fprintln(w, "# TYPE vaultsmith_attestation_keyring_reload_total counter")
	fmt.Fprintf(w, "vaultsmith_attestation_keyring_reload_total{outcome=\"success\"} %d\n", reloadSuccesses)
	fmt.Fprintf(w, "vaultsmith_attestation_keyring_reload_total{outcome=\"failed\"} %d\n", reloadFailures)
	fmt.Fprintln(w, "# TYPE vaultsmith_attestation_keyring_loaded gauge")
	fmt.Fprintf(w, "vaultsmith_attestation_keyring_loaded %d\n", loaded)
}

func attestationOutcomeFromResponse(w http.ResponseWriter) string {
	status := http.StatusInternalServerError
	if recorder, ok := w.(*statusRecordingResponseWriter); ok {
		status = recorder.statusCode()
	}
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return "invalid"
	case http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return "failed"
	}
}

func attestationOutcomeFromError(err error) string {
	switch {
	case vaultservice.HasCode(err, vaultservice.CodeInvalidRequest):
		return "invalid"
	case vaultservice.HasCode(err, vaultservice.CodeFeatureUnavailable):
		return "feature_unavailable"
	case vaultservice.HasCode(err, vaultservice.CodeAttestationBusy):
		return "busy"
	case vaultservice.HasCode(err, vaultservice.CodeAttestationUnavailable):
		return "unavailable"
	default:
		return "failed"
	}
}

func writeOutcomeCounter(w http.ResponseWriter, name string, values map[string]uint64, outcomes []string) {
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	for _, outcome := range outcomes {
		fmt.Fprintf(w, "%s{outcome=%q} %d\n", name, outcome, values[outcome])
	}
}
