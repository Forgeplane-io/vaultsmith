package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/httpapi"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const releaseMinimumPodMemoryBytes int64 = 2 << 30

type workload struct {
	Name               string            `json:"name"`
	Transport          string            `json:"transport"`
	AuthenticationKind string            `json:"authentication_kind"`
	Operation          string            `json:"operation"`
	RequestBodyBytes   int               `json:"request_body_bytes"`
	ExpectedStatus     int               `json:"expected_status"`
	Path               string            `json:"-"`
	Body               string            `json:"-"`
	Headers            map[string]string `json:"-"`
}

type candidateResult struct {
	Capacity               int               `json:"capacity"`
	RequestedDurationSecs  float64           `json:"requested_duration_seconds"`
	MeasuredDurationSecs   float64           `json:"measured_duration_seconds"`
	BaselineRSSBytes       int64             `json:"baseline_rss_bytes"`
	PeakRSSBytes           int64             `json:"peak_rss_bytes"`
	PerRequestPeakRSSBytes map[string]int64  `json:"per_request_peak_rss_bytes"`
	PeakLeases             int               `json:"peak_leases"`
	CompletedRequests      uint64            `json:"completed_requests"`
	SaturationRejections   uint64            `json:"saturation_rejections"`
	UnexpectedFailures     uint64            `json:"unexpected_failures"`
	ThroughputPerSecond    float64           `json:"throughput_per_second"`
	P50Millis              float64           `json:"p50_ms"`
	P95Millis              float64           `json:"p95_ms"`
	P99Millis              float64           `json:"p99_ms"`
	CPUSeconds             float64           `json:"cpu_seconds"`
	CompletedByWorkload    map[string]uint64 `json:"completed_by_workload"`
	AdmissionRejectionRead uint64            `json:"admission_rejection_metric"`
}

type saturationContract struct {
	HTTPStatus        int    `json:"http_status"`
	ErrorCode         string `json:"error_code"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

type receipt struct {
	GeneratedAt             string             `json:"generated_at"`
	ReleaseQualified        bool               `json:"release_qualified"`
	GOOS                    string             `json:"goos"`
	GOARCH                  string             `json:"goarch"`
	GoVersion               string             `json:"go_version"`
	HostCPU                 string             `json:"host_cpu"`
	HostRAMBytes            string             `json:"host_ram_bytes"`
	ContainerCPU            int                `json:"container_cpu"`
	ContainerRAMBytes       string             `json:"container_ram_bytes"`
	GOMAXPROCS              int                `json:"gomaxprocs"`
	ProfileCount            int                `json:"profile_count"`
	RequestBodyLimitBytes   int                `json:"request_body_limit_bytes"`
	CandidateCapacities     []int              `json:"candidate_capacities"`
	SelectedCapacity        int                `json:"selected_capacity"`
	MinimumPodMemoryBytes   int64              `json:"minimum_pod_memory_bytes"`
	Concurrency             int                `json:"concurrency"`
	Workloads               []workload         `json:"workloads"`
	Candidates              []candidateResult  `json:"candidates"`
	Saturation              saturationContract `json:"saturation_response"`
	AdmissionMetrics        []string           `json:"admission_metrics"`
	SelectionBasis          string             `json:"selection_basis"`
	MemoryThresholdBasis    string             `json:"memory_threshold_basis"`
	ThresholdExceededEffect string             `json:"threshold_exceeded_effect"`
	Remediation             string             `json:"remediation"`
}

type benchmarkFixture struct {
	profiles  []httpapi.Profile
	executor  vaultservice.Executor
	workload  []workload
	issuer    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	policyDir string
	policy    string
}

func (f benchmarkFixture) Close() {
	if f.issuer != nil {
		f.issuer.Close()
	}
	if f.policyDir != "" {
		_ = os.RemoveAll(f.policyDir)
	}
}

type executorResolver struct {
	configured config.Executor
}

func (r executorResolver) ForProfile(profileID string) (vaultservice.ProfileExecutor, error) {
	return r.configured.ForProfile(profileID)
}

func main() {
	candidateText := flag.String("candidates", "1,2,4,8,16", "comma-separated admission capacities to evaluate")
	selected := flag.Int("selected", vaultservice.MaxRuntimeAdmissionCapacity, "compiled capacity selected from the candidates")
	concurrency := flag.Int("concurrency", vaultservice.MaxRuntimeAdmissionCapacity*2, "concurrent callers")
	duration := flag.Duration("duration", 5*time.Second, "measurement duration for each candidate")
	profileCount := flag.Int("profiles", 4, "synthetic configured profile count")
	release := flag.Bool("release", false, "require the Linux/amd64 2 GiB release envelope")
	flag.Parse()

	candidates, err := parseCandidates(*candidateText)
	if err != nil {
		fatalf("parse candidates: %v", err)
	}
	if !containsCandidate(candidates, *selected) {
		fatalf("selected capacity %d is not a candidate", *selected)
	}
	if *selected != vaultservice.MaxRuntimeAdmissionCapacity {
		fatalf("selected capacity %d does not match compiled capacity %d", *selected, vaultservice.MaxRuntimeAdmissionCapacity)
	}
	if *concurrency <= *selected {
		fatalf("concurrency must exceed selected capacity %d to observe saturation", *selected)
	}
	if *duration <= 0 {
		fatalf("duration must be positive")
	}
	if *profileCount < 2 {
		fatalf("at least two profiles are required for the rotate workload")
	}
	containerLimit, containerLimitKnown := numericContainerRAM()
	if err := validateBenchmarkEnvironment(*release, runtime.GOOS, runtime.GOARCH, containerLimit, containerLimitKnown); err != nil {
		fatalf("benchmark environment: %v", err)
	}

	fixture, err := newBenchmarkFixture(*profileCount)
	if err != nil {
		fatalf("create real Vaultsmith fixture: %v", err)
	}
	defer fixture.Close()
	results := make([]candidateResult, 0, len(candidates))
	for _, capacity := range candidates {
		result, err := runCandidate(fixture, capacity, *concurrency, *duration)
		if err != nil {
			fatalf("benchmark capacity %d: %v", capacity, err)
		}
		results = append(results, result)
	}
	selectedResult := findCandidate(results, *selected)
	if selectedResult == nil || selectedResult.UnexpectedFailures != 0 || selectedResult.SaturationRejections == 0 {
		fatalf("selected capacity did not complete cleanly with observed saturation")
	}
	if selectedResult.PeakRSSBytes <= selectedResult.BaselineRSSBytes {
		fatalf("selected capacity did not produce a measurable RSS increase")
	}
	if selectedResult.PeakLeases != *selected {
		fatalf("selected capacity peak leases %d did not reach configured capacity %d", selectedResult.PeakLeases, *selected)
	}
	if selectedResult.PeakRSSBytes >= releaseMinimumPodMemoryBytes {
		fatalf("selected capacity peak RSS %d exceeded release threshold %d", selectedResult.PeakRSSBytes, releaseMinimumPodMemoryBytes)
	}
	for _, workload := range fixture.workload {
		if selectedResult.CompletedByWorkload[workload.Name] == 0 {
			fatalf("selected capacity did not complete workload %q", workload.Name)
		}
		peak, ok := selectedResult.PerRequestPeakRSSBytes[workload.Name]
		if !ok || peak <= 0 {
			fatalf("selected capacity did not record a per-request RSS peak for workload %q", workload.Name)
		}
		if peak >= releaseMinimumPodMemoryBytes {
			fatalf("selected capacity workload %q peak RSS %d exceeded release threshold %d", workload.Name, peak, releaseMinimumPodMemoryBytes)
		}
	}
	if selectedResult.AdmissionRejectionRead != selectedResult.SaturationRejections {
		fatalf("selected capacity saturation responses %d do not match admission metric %d", selectedResult.SaturationRejections, selectedResult.AdmissionRejectionRead)
	}
	memoryBasis := "development run; not a release receipt unless -release validates Linux/amd64 and an exact 2 GiB cgroup limit"
	if *release {
		memoryBasis = fmt.Sprintf("%d bytes is the exact 2 GiB cgroup limit used to qualify the selected capacity; the selected baseline and peak RSS are recorded in the matching candidate row", releaseMinimumPodMemoryBytes)
	}

	out := receipt{
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		ReleaseQualified:      *release,
		GOOS:                  runtime.GOOS,
		GOARCH:                runtime.GOARCH,
		GoVersion:             runtime.Version(),
		HostCPU:               getenvDefault("BENCH_HOST_CPU", "unknown"),
		HostRAMBytes:          getenvDefault("BENCH_HOST_RAM_BYTES", "unknown"),
		ContainerCPU:          runtime.NumCPU(),
		ContainerRAMBytes:     containerRAM(),
		GOMAXPROCS:            runtime.GOMAXPROCS(0),
		ProfileCount:          *profileCount,
		RequestBodyLimitBytes: httpapi.MaxRequestBodyBytes,
		CandidateCapacities:   candidates,
		SelectedCapacity:      *selected,
		MinimumPodMemoryBytes: releaseMinimumPodMemoryBytes,
		Concurrency:           *concurrency,
		Workloads:             fixture.workload,
		Candidates:            results,
		Saturation: saturationContract{
			HTTPStatus:        http.StatusServiceUnavailable,
			ErrorCode:         "temporarily_unavailable",
			RetryAfterSeconds: 1,
		},
		AdmissionMetrics: []string{
			"vaultsmith_operation_admission_capacity",
			"vaultsmith_operation_admission_in_use",
			"vaultsmith_operation_admission_rejections_total",
		},
		SelectionBasis:          fmt.Sprintf("capacity %d is the reviewed compiled tripwire; all candidates ran real canonical REST, legacy REST, and MCP decoders with session, delegated-user Bearer, client-credentials Bearer, and anonymous malformed traffic through the shared service and Ansible Vault AES256/PBKDF2 executor, while excess callers were rejected before body retention", *selected),
		MemoryThresholdBasis:    memoryBasis,
		ThresholdExceededEffect: "a pod below this qualified memory limit is outside the release envelope and can be OOM-killed during concurrent maximum-size requests",
		Remediation:             "rerun scripts/admission-benchmark.sh on the release architecture; if selected peak RSS reaches the threshold or unexpected failures occur, lower MaxRuntimeAdmissionCapacity, rerun all candidates, update this receipt, and set pod memory no lower than the newly qualified threshold",
	}
	printReceipt(out)
}

func newBenchmarkFixture(profileCount int) (benchmarkFixture, error) {
	rawProfiles := make([]map[string]string, 0, profileCount)
	passwords := make(map[string]string, profileCount)
	profiles := make([]httpapi.Profile, 0, profileCount)
	for index := 0; index < profileCount; index++ {
		id := fmt.Sprintf("bench-%d", index)
		passwordEnv := fmt.Sprintf("BENCH_PASSWORD_%d", index)
		rawProfiles = append(rawProfiles, map[string]string{"id": id, "label": fmt.Sprintf("Synthetic %d", index), "passwordEnv": passwordEnv})
		passwords[passwordEnv] = fmt.Sprintf("synthetic-benchmark-password-%d", index)
		profiles = append(profiles, httpapi.Profile{ID: id, Label: fmt.Sprintf("Synthetic %d", index)})
	}
	encodedProfiles, err := json.Marshal(rawProfiles)
	if err != nil {
		return benchmarkFixture{}, err
	}
	loaded, err := config.LoadJSON(string(encodedProfiles), func(name string) (string, bool) {
		value, ok := passwords[name]
		return value, ok
	})
	if err != nil {
		return benchmarkFixture{}, err
	}

	plaintext := strings.Repeat("p", vaultservice.MaxPlaintextBytes)
	source, err := loaded.Executor().ForProfile("bench-0")
	if err != nil {
		return benchmarkFixture{}, err
	}
	vaultText, err := source.Encrypt(context.Background(), plaintext)
	if err != nil {
		return benchmarkFixture{}, err
	}
	body := func(value any) (string, error) {
		encoded, marshalErr := json.Marshal(value)
		return string(encoded), marshalErr
	}
	encryptBody, err := body(map[string]string{"plaintext": plaintext})
	if err != nil {
		return benchmarkFixture{}, err
	}
	decryptBody, err := body(map[string]string{"vaultText": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	rotateBody, err := body(map[string]string{"sourceProfileId": "bench-0", "destinationProfileId": "bench-1", "vaultText": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	malformedBody := strings.Repeat("x", httpapi.MaxRequestBodyBytes)
	legacyEncryptBody, err := body(map[string]string{"profileId": "bench-0", "mode": "encrypt", "value": plaintext})
	if err != nil {
		return benchmarkFixture{}, err
	}
	legacyDecryptBody, err := body(map[string]string{"profileId": "bench-0", "mode": "decrypt", "value": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	legacyRotateBody, err := body(map[string]string{"mode": "rotate", "sourceProfileId": "bench-0", "destinationProfileId": "bench-1", "value": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	mcpBody := func(name string, arguments map[string]string) (string, error) {
		return body(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      name,
				"arguments": arguments,
				"_meta": map[string]any{
					"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
					"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				},
			},
		})
	}
	mcpEncryptBody, err := mcpBody("encrypt", map[string]string{"profileId": "bench-0", "plaintext": plaintext})
	if err != nil {
		return benchmarkFixture{}, err
	}
	mcpDecryptBody, err := mcpBody("decrypt", map[string]string{"profileId": "bench-0", "vaultText": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	mcpRotateBody, err := mcpBody("rotate", map[string]string{"sourceProfileId": "bench-0", "destinationProfileId": "bench-1", "vaultText": vaultText})
	if err != nil {
		return benchmarkFixture{}, err
	}
	mcpHeaders := func(name string) map[string]string {
		return map[string]string{
			"Accept":               "application/json, text/event-stream",
			"MCP-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             name,
		}
	}
	workloads := []workload{
		{Name: "canonical_encrypt_max_plaintext", Transport: "canonical_rest", AuthenticationKind: "bearer_delegated_user", Operation: "encrypt", RequestBodyBytes: len(encryptBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/profiles/bench-0/encrypt", Body: encryptBody},
		{Name: "canonical_decrypt_valid_max_plaintext_vault", Transport: "canonical_rest", AuthenticationKind: "bearer_client_credentials", Operation: "decrypt", RequestBodyBytes: len(decryptBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/profiles/bench-0/decrypt", Body: decryptBody},
		{Name: "canonical_rotate_valid_max_plaintext_vault", Transport: "canonical_rest", AuthenticationKind: "bearer_delegated_user", Operation: "rotate", RequestBodyBytes: len(rotateBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/rotations", Body: rotateBody},
		{Name: "legacy_encrypt_max_plaintext", Transport: "legacy_rest", AuthenticationKind: "session", Operation: "encrypt", RequestBodyBytes: len(legacyEncryptBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/operations", Body: legacyEncryptBody},
		{Name: "legacy_decrypt_valid_max_plaintext_vault", Transport: "legacy_rest", AuthenticationKind: "session", Operation: "decrypt", RequestBodyBytes: len(legacyDecryptBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/operations", Body: legacyDecryptBody},
		{Name: "legacy_rotate_valid_max_plaintext_vault", Transport: "legacy_rest", AuthenticationKind: "session", Operation: "rotate", RequestBodyBytes: len(legacyRotateBody), ExpectedStatus: http.StatusOK, Path: "/api/v1/operations", Body: legacyRotateBody},
		{Name: "mcp_encrypt_max_plaintext", Transport: "mcp", AuthenticationKind: "bearer_client_credentials", Operation: "encrypt", RequestBodyBytes: len(mcpEncryptBody), ExpectedStatus: http.StatusOK, Path: "/mcp", Body: mcpEncryptBody, Headers: mcpHeaders("encrypt")},
		{Name: "mcp_decrypt_valid_max_plaintext_vault", Transport: "mcp", AuthenticationKind: "bearer_delegated_user", Operation: "decrypt", RequestBodyBytes: len(mcpDecryptBody), ExpectedStatus: http.StatusOK, Path: "/mcp", Body: mcpDecryptBody, Headers: mcpHeaders("decrypt")},
		{Name: "mcp_rotate_valid_max_plaintext_vault", Transport: "mcp", AuthenticationKind: "bearer_client_credentials", Operation: "rotate", RequestBodyBytes: len(mcpRotateBody), ExpectedStatus: http.StatusOK, Path: "/mcp", Body: mcpRotateBody, Headers: mcpHeaders("rotate")},
		{Name: "malformed_rest_body_at_http_limit", Transport: "canonical_rest", AuthenticationKind: "anonymous", Operation: "decode_rejection", RequestBodyBytes: len(malformedBody), ExpectedStatus: http.StatusBadRequest, Path: "/api/v1/profiles/bench-0/encrypt", Body: malformedBody},
		{Name: "malformed_mcp_body_at_http_limit", Transport: "mcp", AuthenticationKind: "anonymous", Operation: "decode_rejection", RequestBodyBytes: len(malformedBody), ExpectedStatus: http.StatusBadRequest, Path: "/mcp", Body: malformedBody, Headers: map[string]string{"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}},
	}

	fixture, err := newAuthenticatedBenchmarkFixture(profiles)
	if err != nil {
		return benchmarkFixture{}, err
	}
	fixture.executor = executorResolver{configured: loaded.Executor()}
	fixture.workload = workloads
	return fixture, nil
}

func newAuthenticatedBenchmarkFixture(profiles []httpapi.Profile) (benchmarkFixture, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return benchmarkFixture{}, fmt.Errorf("generate benchmark signing key: %w", err)
	}
	fixture := &benchmarkFixture{profiles: profiles, key: key, kid: "benchmark-kid"}
	publicKey := jose.JSONWebKey{Key: &key.PublicKey, KeyID: fixture.kid, Algorithm: string(jose.RS256), Use: "sig"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 fixture.issuer.URL,
			"jwks_uri":               fixture.issuer.URL + "/jwks",
			"authorization_endpoint": fixture.issuer.URL + "/authorize",
			"token_endpoint":         fixture.issuer.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
	})
	fixture.issuer = httptest.NewTLSServer(mux)

	policyDir, err := os.MkdirTemp("", "vaultsmith-admission-policy-")
	if err != nil {
		fixture.Close()
		return benchmarkFixture{}, fmt.Errorf("create benchmark policy directory: %w", err)
	}
	fixture.policyDir = policyDir
	fixture.policy = filepath.Join(policyDir, "policy.csv")
	var policy strings.Builder
	policy.WriteString("g, group:admins, role:admin\n")
	policy.WriteString("p, role:admin, profiles, profiles:list, allow\n")
	for _, profile := range profiles {
		fmt.Fprintf(&policy, "p, role:admin, profile:%s, encrypt, allow\n", profile.ID)
		fmt.Fprintf(&policy, "p, role:admin, profile:%s, decrypt, allow\n", profile.ID)
	}
	if err := os.WriteFile(fixture.policy, []byte(policy.String()), 0o600); err != nil {
		fixture.Close()
		return benchmarkFixture{}, fmt.Errorf("write benchmark policy: %w", err)
	}
	return *fixture, nil
}

type benchmarkHandlers struct {
	native         http.Handler
	anonymous      http.Handler
	sessionCookie  *http.Cookie
	csrfCookie     *http.Cookie
	csrfToken      string
	delegatedToken string
	clientToken    string
}

func newBenchmarkHandlers(fixture benchmarkFixture, admission *vaultservice.Admission) (benchmarkHandlers, error) {
	const publicBaseURL = "https://vaultsmith.example.test"
	cfg := config.AuthConfig{
		Mode: config.AuthModeNative,
		OIDC: config.OIDCConfig{
			IssuerURL:     fixture.issuer.URL,
			PublicBaseURL: publicBaseURL,
			GroupsClaim:   "groups",
		},
		Session: config.SessionConfig{
			CookieName:       "__Host-vaultsmith_session",
			AbsoluteLifetime: time.Hour,
			IdleLifetime:     time.Minute,
			Secure:           true,
			SameSite:         http.SameSiteLaxMode,
		},
		CSRF: config.CSRFConfig{Secret: "01234567890123456789012345678901"},
	}
	verifier, err := authn.NewAccessTokenVerifier(context.Background(), cfg.OIDC.IssuerURL, cfg.OIDC.PublicBaseURL, cfg.OIDC.GroupsClaim, fixture.issuer.Client())
	if err != nil {
		return benchmarkHandlers{}, fmt.Errorf("create benchmark access-token verifier: %w", err)
	}
	sessions := authn.NewSessionManager(memstore.New(), cfg.Session)
	authenticator := &authn.Authenticator{Config: cfg, Sessions: sessions, Access: verifier}
	profileIDs := make([]string, 0, len(fixture.profiles))
	for _, profile := range fixture.profiles {
		profileIDs = append(profileIDs, profile.ID)
	}
	policy, err := authz.LoadPolicy(fixture.policy, profileIDs)
	if err != nil {
		return benchmarkHandlers{}, fmt.Errorf("load benchmark policy: %w", err)
	}
	authorizer, err := authz.NewAuthorizer(policy)
	if err != nil {
		return benchmarkHandlers{}, fmt.Errorf("create benchmark authorizer: %w", err)
	}
	nativeAPI := httpapi.NewWithDependencies(fixture.profiles, fixture.executor, httpapi.Dependencies{
		Auth:       authenticator,
		Authorizer: authorizer,
		AuthConfig: cfg,
		Admission:  admission,
	})
	native := httpapi.WrapSecurityWithOptions(nativeAPI, cfg, httpapi.SecurityOptions{Auth: authenticator, MCPEnabled: true})
	offConfig := config.AuthConfig{Mode: config.AuthModeOff}
	offAPI := httpapi.NewWithDependencies(fixture.profiles, fixture.executor, httpapi.Dependencies{AuthConfig: offConfig, Admission: admission})
	anonymous := httpapi.WrapSecurityWithOptions(offAPI, offConfig, httpapi.SecurityOptions{MCPEnabled: true})

	sessionContext, err := sessions.Load(context.Background(), "")
	if err != nil {
		return benchmarkHandlers{}, fmt.Errorf("load benchmark session: %w", err)
	}
	authn.StorePrincipal(sessionContext, sessions, authn.Principal{
		Issuer:    fixture.issuer.URL,
		Subject:   "benchmark-session-user",
		Groups:    []string{"admins"},
		ExpiresAt: time.Now().Add(time.Hour),
	}, "")
	sessionToken, _, err := sessions.Commit(sessionContext)
	if err != nil {
		return benchmarkHandlers{}, fmt.Errorf("commit benchmark session: %w", err)
	}
	sessionCookie := &http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken, Path: "/", Secure: true, HttpOnly: true}
	bootstrapRequest := httptest.NewRequest(http.MethodGet, publicBaseURL+"/api/v1/session", nil)
	bootstrapRequest.AddCookie(sessionCookie)
	bootstrapResponse := httptest.NewRecorder()
	native.ServeHTTP(bootstrapResponse, bootstrapRequest)
	if bootstrapResponse.Code != http.StatusOK {
		return benchmarkHandlers{}, fmt.Errorf("bootstrap benchmark session: status %d", bootstrapResponse.Code)
	}
	var bootstrap struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(bootstrapResponse.Body.Bytes(), &bootstrap); err != nil || bootstrap.CSRFToken == "" {
		return benchmarkHandlers{}, fmt.Errorf("decode benchmark CSRF bootstrap")
	}
	var csrfCookie *http.Cookie
	for _, cookie := range bootstrapResponse.Result().Cookies() {
		if cookie.Name != cfg.Session.CookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		return benchmarkHandlers{}, fmt.Errorf("benchmark CSRF cookie was not issued")
	}
	delegatedToken, err := fixture.signAccessToken(publicBaseURL, "benchmark-user", "vaultsmith-browser")
	if err != nil {
		return benchmarkHandlers{}, err
	}
	clientToken, err := fixture.signAccessToken(publicBaseURL, "client:vaultsmith-ci", "vaultsmith-ci")
	if err != nil {
		return benchmarkHandlers{}, err
	}
	return benchmarkHandlers{
		native:         native,
		anonymous:      anonymous,
		sessionCookie:  sessionCookie,
		csrfCookie:     csrfCookie,
		csrfToken:      bootstrap.CSRFToken,
		delegatedToken: delegatedToken,
		clientToken:    clientToken,
	}, nil
}

func (f benchmarkFixture) signAccessToken(audience, subject, clientID string) (string, error) {
	options := (&jose.SignerOptions{}).WithType("at+jwt")
	options.WithHeader(jose.HeaderKey("kid"), f.kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, options)
	if err != nil {
		return "", fmt.Errorf("create benchmark token signer: %w", err)
	}
	now := time.Now().UTC()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:    f.issuer.URL,
		Subject:   subject,
		Audience:  jwt.Audience{audience},
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ID:        "benchmark-" + clientID,
	}).Claims(map[string]any{
		"client_id": clientID,
		"scope":     "vaultsmith.profile.read vaultsmith.encrypt vaultsmith.decrypt vaultsmith.rotate",
		"groups":    []string{"admins"},
	}).Serialize()
	if err != nil {
		return "", fmt.Errorf("serialize benchmark access token: %w", err)
	}
	return raw, nil
}

func (h benchmarkHandlers) serve(item workload) (int, http.Header) {
	request := httptest.NewRequest(http.MethodPost, "https://vaultsmith.example.test"+item.Path, strings.NewReader(item.Body))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range item.Headers {
		request.Header.Set(name, value)
	}
	handler := h.native
	switch item.AuthenticationKind {
	case "anonymous":
		handler = h.anonymous
	case "session":
		request.AddCookie(h.sessionCookie)
		request.AddCookie(h.csrfCookie)
		request.Header.Set("X-CSRF-Token", h.csrfToken)
		request.Header.Set("Origin", "https://vaultsmith.example.test")
	case "bearer_delegated_user":
		request.Header.Set("Authorization", "Bearer "+h.delegatedToken)
	case "bearer_client_credentials":
		request.Header.Set("Authorization", "Bearer "+h.clientToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code, response.Header()
}

type measuredRequest struct {
	status int
	header http.Header
}

func measurePerRequestPeaks(handlers benchmarkHandlers, workloads []workload) (map[string]int64, error) {
	peaks := make(map[string]int64, len(workloads))
	for _, item := range workloads {
		runtime.GC()
		debug.FreeOSMemory()
		baseline, err := currentRSSBytes()
		if err != nil {
			return nil, fmt.Errorf("measure workload %q baseline RSS: %w", item.Name, err)
		}
		peak := baseline
		result := make(chan measuredRequest, 1)
		go func(item workload) {
			status, header := handlers.serve(item)
			result <- measuredRequest{status: status, header: header}
		}(item)

		ticker := time.NewTicker(time.Millisecond)
		for {
			select {
			case observed := <-result:
				if rss, rssErr := currentRSSBytes(); rssErr == nil && rss > peak {
					peak = rss
				}
				ticker.Stop()
				if observed.status != item.ExpectedStatus {
					return nil, fmt.Errorf("measure workload %q: status %d, want %d", item.Name, observed.status, item.ExpectedStatus)
				}
				peaks[item.Name] = peak
				goto nextWorkload
			case <-ticker.C:
				rss, rssErr := currentRSSBytes()
				if rssErr != nil {
					ticker.Stop()
					return nil, fmt.Errorf("measure workload %q peak RSS: %w", item.Name, rssErr)
				}
				if rss > peak {
					peak = rss
				}
			}
		}
	nextWorkload:
	}
	return peaks, nil
}

func runCandidate(fixture benchmarkFixture, capacity, concurrency int, duration time.Duration) (candidateResult, error) {
	admission, err := vaultservice.NewAdmission(capacity)
	if err != nil {
		return candidateResult{}, err
	}
	handlers, err := newBenchmarkHandlers(fixture, admission)
	if err != nil {
		return candidateResult{}, err
	}
	perRequestPeaks, err := measurePerRequestPeaks(handlers, fixture.workload)
	if err != nil {
		return candidateResult{}, err
	}

	runtime.GC()
	debug.FreeOSMemory()
	baseline, err := currentRSSBytes()
	if err != nil {
		return candidateResult{}, err
	}
	var peakRSS atomic.Int64
	peakRSS.Store(baseline)
	var peakLeases atomic.Int64
	samplerDone := make(chan struct{})
	stopSampler := make(chan struct{})
	go sampleRuntime(admission, &peakRSS, &peakLeases, stopSampler, samplerDone)

	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	start := time.Now()
	stop := start.Add(duration)
	var attempts atomic.Uint64
	var completed atomic.Uint64
	var saturated atomic.Uint64
	var unexpected atomic.Uint64
	completedByWorkload := make([]atomic.Uint64, len(fixture.workload))
	latencies := sampledDurations{limit: 200000}

	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for time.Now().Before(stop) {
				index := int(attempts.Add(1)-1) % len(fixture.workload)
				item := fixture.workload[index]
				begin := time.Now()
				code, responseHeader := handlers.serve(item)
				switch {
				case code == item.ExpectedStatus:
					completed.Add(1)
					completedByWorkload[index].Add(1)
					latencies.add(time.Since(begin))
				case code == http.StatusServiceUnavailable && responseHeader.Get("Retry-After") == "1":
					saturated.Add(1)
					time.Sleep(100 * time.Microsecond)
				default:
					unexpected.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(start)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	close(stopSampler)
	<-samplerDone

	byWorkload := make(map[string]uint64, len(fixture.workload))
	for index, item := range fixture.workload {
		byWorkload[item.Name] = completedByWorkload[index].Load()
	}
	return candidateResult{
		Capacity:               capacity,
		RequestedDurationSecs:  duration.Seconds(),
		MeasuredDurationSecs:   elapsed.Seconds(),
		BaselineRSSBytes:       baseline,
		PeakRSSBytes:           peakRSS.Load(),
		PerRequestPeakRSSBytes: perRequestPeaks,
		PeakLeases:             int(peakLeases.Load()),
		CompletedRequests:      completed.Load(),
		SaturationRejections:   saturated.Load(),
		UnexpectedFailures:     unexpected.Load(),
		ThroughputPerSecond:    float64(completed.Load()) / elapsed.Seconds(),
		P50Millis:              millis(latencies.quantile(0.50)),
		P95Millis:              millis(latencies.quantile(0.95)),
		P99Millis:              millis(latencies.quantile(0.99)),
		CPUSeconds:             cpuSeconds(after) - cpuSeconds(before),
		CompletedByWorkload:    byWorkload,
		AdmissionRejectionRead: admission.Rejections(),
	}, nil
}

func sampleRuntime(admission *vaultservice.Admission, peakRSS, peakLeases *atomic.Int64, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if rss, err := currentRSSBytes(); err == nil {
			storeMax(peakRSS, rss)
		}
		storeMax(peakLeases, int64(admission.InUse()))
		select {
		case <-stop:
			if rss, err := currentRSSBytes(); err == nil {
				storeMax(peakRSS, rss)
			}
			storeMax(peakLeases, int64(admission.InUse()))
			return
		case <-ticker.C:
		}
	}
}

func storeMax(target *atomic.Int64, value int64) {
	for current := target.Load(); value > current; current = target.Load() {
		if target.CompareAndSwap(current, value) {
			return
		}
	}
}

func parseCandidates(value string) ([]int, error) {
	seen := map[int]struct{}{}
	var candidates []int
	for _, raw := range strings.Split(value, ",") {
		capacity, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || capacity < 1 || capacity > vaultservice.MaxRuntimeAdmissionCapacity {
			return nil, fmt.Errorf("capacity %q must be between 1 and %d", raw, vaultservice.MaxRuntimeAdmissionCapacity)
		}
		if _, duplicate := seen[capacity]; duplicate {
			return nil, fmt.Errorf("capacity %d is duplicated", capacity)
		}
		seen[capacity] = struct{}{}
		candidates = append(candidates, capacity)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("at least one capacity is required")
	}
	sort.Ints(candidates)
	return candidates, nil
}

func containsCandidate(candidates []int, selected int) bool {
	for _, candidate := range candidates {
		if candidate == selected {
			return true
		}
	}
	return false
}

func findCandidate(results []candidateResult, capacity int) *candidateResult {
	for index := range results {
		if results[index].Capacity == capacity {
			return &results[index]
		}
	}
	return nil
}

func validateBenchmarkEnvironment(release bool, goos, goarch string, containerLimit int64, containerLimitKnown bool) error {
	if !release {
		if containerLimitKnown && containerLimit < releaseMinimumPodMemoryBytes {
			return fmt.Errorf("container memory limit %d is below benchmark threshold %d", containerLimit, releaseMinimumPodMemoryBytes)
		}
		return nil
	}
	if goos != "linux" || goarch != "amd64" {
		return fmt.Errorf("release receipt requires linux/amd64, observed %s/%s", goos, goarch)
	}
	if !containerLimitKnown {
		return errors.New("release receipt requires a numeric cgroup memory limit")
	}
	if containerLimit != releaseMinimumPodMemoryBytes {
		return fmt.Errorf("release receipt requires exact cgroup memory limit %d, observed %d", releaseMinimumPodMemoryBytes, containerLimit)
	}
	return nil
}

type sampledDurations struct {
	mu     sync.Mutex
	values []time.Duration
	limit  int
}

func (s *sampledDurations) add(value time.Duration) {
	s.mu.Lock()
	if len(s.values) < s.limit {
		s.values = append(s.values, value)
	}
	s.mu.Unlock()
}

func (s *sampledDurations) quantile(q float64) time.Duration {
	s.mu.Lock()
	values := append([]time.Duration(nil), s.values...)
	s.mu.Unlock()
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := int(q * float64(len(values)-1))
	return values[index]
}

func printReceipt(out receipt) {
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fatalf("marshal receipt: %v", err)
	}
	fmt.Println("# Vaultsmith Admission Benchmark Receipt")
	fmt.Println()
	fmt.Println("This release receipt measures real canonical REST, legacy REST, and MCP decoders with session, delegated-user Bearer, client-credentials Bearer, and anonymous malformed traffic through the shared Vaultsmith service and Ansible Vault AES256/PBKDF2 executor. The malformed REST and MCP workloads each reach the 8 MiB HTTP body limit and are expected to fail strict JSON decoding. Each candidate records absolute per-request and concurrent process RSS peaks.")
	fmt.Println()
	fmt.Println("```json")
	fmt.Println(string(encoded))
	fmt.Println("```")
	fmt.Println()
	fmt.Printf("The minimum pod memory limit is **%d bytes (2 GiB)** because this is the fixed container envelope used to qualify capacity %d. A lower limit is not covered by this receipt. If observed RSS reaches the limit, the pod can be OOM-killed. Lower the compiled capacity and rerun `scripts/admission-benchmark.sh`; do not raise the cap without a new receipt.\n", out.MinimumPodMemoryBytes, out.SelectedCapacity)
}

func currentRSSBytes() (int64, error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			kib, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr == nil {
				return kib * 1024, nil
			}
			break
		}
	}
	// Linux release receipts use VmRSS above. This fallback keeps the harness
	// runnable on development hosts that do not expose procfs; it measures the
	// Go runtime's mapped memory and is not accepted as a release RSS receipt.
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	if stats.Sys == 0 {
		return 0, errors.New("resident memory is unavailable")
	}
	return int64(stats.Sys), nil
}

func cpuSeconds(usage syscall.Rusage) float64 {
	return timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime)
}

func timevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1e6
}

func millis(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func containerRAM() string {
	if value, ok := numericContainerRAM(); ok {
		return strconv.FormatInt(value, 10)
	}
	return "unknown"
}

func numericContainerRAM() (int64, bool) {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value == "" || value == "max" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil && parsed > 0 {
			return parsed, true
		}
	}
	return 0, false
}

func getenvDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
