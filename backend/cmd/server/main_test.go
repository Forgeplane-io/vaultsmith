package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

const httpStartupHelperEnv = "VAULTSMITH_TEST_HTTP_STARTUP_HELPER"

// Match smoke.sh's startup budget. Local off-mode baseline readiness was 14-46ms;
// this is a hang tripwire, not a performance requirement. If exceeded, inspect
// fixture/port availability and host load before remeasuring and revising it.
const httpStartupBudget = 10 * time.Second

func TestHTTPListenerStartupInSubprocess(t *testing.T) {
	probeIP := nonLoopbackIPv4(t)
	tests := []struct {
		name     string
		mode     string
		address  *string
		explicit bool
		loopback bool
		ipv6     bool
	}{
		{name: "off unset", mode: "off", loopback: true},
		{name: "off empty", mode: "off", address: stringPointer(""), loopback: true},
		{name: "off explicit loopback", mode: "off", address: stringPointer("127.0.0.1"), explicit: true, loopback: true},
		{name: "off explicit wildcard", mode: "off", address: stringPointer(""), explicit: true},
		{name: "off explicit IPv6 loopback", mode: "off", address: stringPointer("::1"), explicit: true, loopback: true, ipv6: true},
		{name: "native unset", mode: "native"},
		{name: "native empty", mode: "native", address: stringPointer("")},
		{name: "native explicit loopback", mode: "native", address: stringPointer("127.0.0.1"), explicit: true, loopback: true},
		{name: "native explicit wildcard", mode: "native", address: stringPointer(""), explicit: true},
		{name: "native explicit IPv6 loopback", mode: "native", address: stringPointer("::1"), explicit: true, loopback: true, ipv6: true},
	}
	// Fixed default-port cases must remain serial; never stop an existing service.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := syntheticStartupEnvironment()
			env = append(env, "AUTH_MODE="+test.mode)
			if test.mode == "native" {
				env = append(env, nativeStartupEnvironment(t, "")...)
			}
			port := "8080"
			connectHost := "127.0.0.1"
			if test.ipv6 {
				connectHost = "::1"
			}
			if test.explicit {
				listener, err := net.Listen("tcp", net.JoinHostPort(connectHost, "0"))
				if err != nil {
					if test.ipv6 {
						t.Skip("IPv6 loopback listener unavailable; enable IPv6 to exercise this explicit binding")
					}
					t.Fatal("cannot allocate explicit listener port")
				}
				port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
				_ = listener.Close()
				env = append(env, "HTTP_ADDR="+net.JoinHostPort(*test.address, port))
			} else if test.address != nil {
				env = append(env, "HTTP_ADDR="+*test.address)
			}
			assertStartupPortAvailable(t, port)
			process := startHTTPStartupHelper(t, env)
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), httpStartupBudget)
			defer cancel()
			transport := &http.Transport{DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(connectHost, port)+"/healthz", nil)
				if err != nil {
					t.Fatal("cannot construct synthetic health request")
				}
				response, err := client.Do(request)
				if err == nil {
					_ = response.Body.Close()
					if response.StatusCode == http.StatusOK {
						break
					}
				}
				select {
				case <-process.done:
					t.Fatal("synthetic server exited before readiness; check startup prerequisites")
				case <-ctx.Done():
					t.Fatalf("startup budget configured=%s observed=%s; inspect fixture, port availability, and host load before revising", httpStartupBudget, time.Since(started))
				case <-ticker.C:
				}
			}
			select {
			case <-process.done:
				t.Fatal("synthetic server exited during readiness; port may have been taken by another process")
			default:
			}
			// Probe actual TCP reachability on this host, not the logged address.
			// No HTTP request or secret material is sent over the non-loopback socket.
			probe, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(probeIP, port))
			if probe != nil {
				_ = probe.Close()
			}
			if ctx.Err() != nil {
				t.Fatalf("socket probe budget configured=%s observed=%s; inspect local network and host load before revising", httpStartupBudget, time.Since(started))
			}
			if test.loopback && !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatal("loopback-only server did not refuse the non-loopback IPv4 connection")
			}
			if !test.loopback && err != nil {
				t.Fatal("wildcard server did not accept the non-loopback IPv4 connection")
			}
			if test.ipv6 {
				probe, err := (&net.Dialer{}).DialContext(ctx, "tcp4", "127.0.0.1:"+port)
				if probe != nil {
					_ = probe.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("explicit IPv6 listener did not refuse IPv4 loopback (socket probe budget configured=%s observed=%s); inspect local network and host load before revising", httpStartupBudget, time.Since(started))
				}
			} else if test.loopback {
				ipv6, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Log("IPv6 loopback unavailable; cross-family refusal not exercised")
				} else {
					_ = ipv6.Close()
					probe, err := (&net.Dialer{}).DialContext(ctx, "tcp6", "[::1]:"+port)
					if probe != nil {
						_ = probe.Close()
					}
					if !errors.Is(err, syscall.ECONNREFUSED) {
						t.Fatalf("IPv4 loopback listener did not refuse IPv6 loopback (socket probe budget configured=%s observed=%s); inspect local network and host load before revising", httpStartupBudget, time.Since(started))
					}
				}
			}
			t.Logf("ready after=%s budget=%s; socket confinement verified (loopback=%t IPv6=%t)", time.Since(started), httpStartupBudget, test.loopback, test.ipv6)
		})
	}
}

func TestHTTPStartupAuthenticationFailuresInSubprocess(t *testing.T) {
	tests := []struct {
		name       string
		mode       *string
		dependency string
		wantError  string
	}{
		{name: "unset mode", wantError: "AUTH_MODE must be explicitly set"},
		{name: "empty mode", mode: stringPointer(""), wantError: "AUTH_MODE must be explicitly set"},
		{name: "blank mode", mode: stringPointer(" "), wantError: "AUTH_MODE must be explicitly set"},
		{name: "invalid mode", mode: stringPointer("invalid"), wantError: "AUTH_MODE must be"},
		{name: "native missing config", mode: stringPointer("native"), wantError: "CSRF_SECRET is required"},
		{name: "native Redis failure", mode: stringPointer("native"), dependency: "redis", wantError: "redis probe connection failed"},
		{name: "native OIDC failure", mode: stringPointer("native"), dependency: "oidc", wantError: "OIDC discovery failed"},
		{name: "native policy failure", mode: stringPointer("native"), dependency: "policy", wantError: "authorization policy unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertStartupPortAvailable(t, "8080")
			env := syntheticStartupEnvironment()
			if test.mode != nil {
				env = append(env, "AUTH_MODE="+*test.mode)
			}
			if test.dependency != "" {
				env = append(env, nativeStartupEnvironment(t, test.dependency)...)
			}
			process := startHTTPStartupHelper(t, env)
			started := time.Now()
			timer := time.NewTimer(httpStartupBudget)
			defer timer.Stop()
			select {
			case <-process.done:
			case <-timer.C:
				t.Fatalf("fail-closed startup budget configured=%s observed=%s; inspect fixture and authentication failure before revising", httpStartupBudget, time.Since(started))
			}
			output, err := os.ReadFile(process.logPath)
			if err != nil {
				t.Fatal("cannot read synthetic startup diagnostic")
			}
			if process.err == nil || !strings.Contains(string(output), test.wantError) {
				t.Fatalf("helper did not fail closed with %q (diagnostic contents withheld)", test.wantError)
			}
			if strings.Contains(string(output), "listening on") || strings.Contains(string(output), "does not authenticate requests") {
				t.Fatal("authentication failure reached listener startup or fell back to off mode")
			}
			assertStartupPortAvailable(t, "8080")
			t.Log("authentication failed closed before listener startup")
		})
	}
}

func TestHTTPStartupHelper(t *testing.T) {
	if os.Getenv(httpStartupHelperEnv) != "1" {
		return
	}
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

type httpStartupProcess struct {
	done    chan struct{}
	err     error // Read only after done is closed.
	logPath string
}

func startHTTPStartupHelper(t *testing.T, env []string) *httpStartupProcess {
	t.Helper()
	process := &httpStartupProcess{done: make(chan struct{}), logPath: filepath.Join(t.TempDir(), "startup.log")}
	logFile, err := os.Create(process.logPath)
	if err != nil {
		t.Fatal("cannot create synthetic startup log")
	}
	t.Cleanup(func() { _ = logFile.Close() })
	command := exec.Command(os.Args[0], "-test.run=^TestHTTPStartupHelper$")
	// Do not inherit credentials, proxies, or application settings from the caller.
	command.Env = append(env, httpStartupHelperEnv+"=1")
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		t.Fatal("cannot start synthetic server subprocess")
	}
	go func() {
		process.err = command.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		select {
		case <-process.done:
			return
		default:
		}
		started := time.Now()
		if err := command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error("cannot signal owned server subprocess")
		}
		timer := time.NewTimer(httpStartupBudget)
		defer timer.Stop()
		select {
		case <-process.done:
			if process.err != nil {
				t.Error("owned server did not shut down cleanly")
			}
		case <-timer.C:
			_ = command.Process.Kill()
			<-process.done
			t.Errorf("cleanup budget configured=%s observed=%s; owned server killed and joined; inspect shutdown before revising", httpStartupBudget, time.Since(started))
		}
	})
	return process
}

func syntheticStartupEnvironment() []string {
	return []string{
		`VAULT_PROFILES_JSON=[{"id":"synthetic","label":"Synthetic","passwordEnv":"VAULT_PASSWORD_SYNTHETIC"}]`,
		"VAULT_PASSWORD_SYNTHETIC=synthetic-listener-fixture",
	}
}

func nativeStartupEnvironment(t *testing.T, failure string) []string {
	t.Helper()
	redis := miniredis.RunT(t)
	redisAddress := redis.Addr()
	if failure == "redis" {
		redis.Close()
	}
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failure == "oidc" || r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer.URL,
			"authorization_endpoint": issuer.URL + "/authorize",
			"token_endpoint":         issuer.URL + "/token",
			"jwks_uri":               issuer.URL + "/jwks",
		})
	}))
	t.Cleanup(issuer.Close)
	directory := t.TempDir()
	caFile := filepath.Join(directory, "synthetic-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0600); err != nil {
		t.Fatal("cannot write synthetic issuer trust fixture")
	}
	policyFile := filepath.Join(directory, "policy.csv")
	if failure != "policy" {
		if err := os.WriteFile(policyFile, []byte("p, role:operator, profiles, profiles:list, allow\n"), 0600); err != nil {
			t.Fatal("cannot write synthetic authorization fixture")
		}
	}
	return []string{
		"CSRF_SECRET=" + strings.Repeat("s", 32),
		"OIDC_ISSUER_URL=" + issuer.URL,
		"OIDC_CA_FILE=" + caFile,
		"OIDC_CLIENT_ID=synthetic-client",
		"OIDC_CLIENT_SECRET=synthetic-client-secret",
		"OIDC_REDIRECT_URL=https://vaultsmith.example.test/auth/callback",
		"PUBLIC_BASE_URL=https://vaultsmith.example.test",
		"REDIS_ADDR=" + redisAddress,
		"REDIS_KEY_PREFIX=vaultsmith:synthetic-startup:",
		"AUTHZ_POLICY_FILE=" + policyFile,
	}
}

func assertStartupPortAvailable(t *testing.T, port string) {
	t.Helper()
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatalf("listener port %s unavailable; rerun in isolation without stopping another service", port)
	}
	_ = listener.Close()
}

func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("cannot enumerate interfaces for listener confinement probe")
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.To4() == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err == nil {
			_ = listener.Close()
			return ip.String()
		}
	}
	t.Skip("no bindable non-loopback IPv4 interface; rerun on a networked host for listener confinement coverage")
	return ""
}
