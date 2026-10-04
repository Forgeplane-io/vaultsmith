package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

// These are fixture-only deadlines, not production budgets. Completed local
// native requests take milliseconds. The one-second completion tripwire leaves
// scheduling headroom over the application deadline but cannot pass by waiting
// for the two-second socket timeout. Logs record progress for revising it.
const (
	uploadApplicationTimeout = 200 * time.Millisecond
	uploadSocketTimeout      = 2 * time.Second
	uploadCompletionBudget   = time.Second
)

func TestHTTP1UploadApplicationDeadline(t *testing.T) {
	for _, test := range []struct {
		name   string
		mcp    bool
		verify bool
		native string
	}{
		{name: "REST"},
		{name: "MCP", mcp: true},
		{name: "REST verifier", verify: true},
		{name: "MCP verifier", mcp: true, verify: true},
		{name: "native REST Bearer", native: "bearer"},
		{name: "native MCP Bearer", native: "bearer", mcp: true},
		{name: "native REST session", native: "session"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.AuthConfig{Mode: config.AuthModeOff}
			admission, err := vaultservice.NewAdmission(1)
			if err != nil {
				t.Fatal(err)
			}
			api := NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{value: "synthetic-output"}, Dependencies{Admission: admission})
			handler := WrapSecurityWithOptions(api, cfg, SecurityOptions{MCPEnabled: test.mcp})
			path := "/api/v1/profiles/dev/encrypt"
			body := `{"plaintext":"synthetic"}`
			tool := "encrypt"
			headers := http.Header{"Content-Type": {"application/json"}}
			var otherAdmission *vaultservice.Admission
			if test.verify {
				service, _ := newHTTPAttestationService(t, newHTTPSyntheticAttestationManager("https://vaultsmith.synthetic.test"), true, 1)
				handler = WrapSecurityWithOptions(attestationHTTPHandler(t, service), cfg, SecurityOptions{MCPEnabled: test.mcp})
				admission = service.VerifierAdmission()
				otherAdmission = service.Admission()
				path = "/api/v1/attestations/verify"
				body = `{}` // A completed malformed control releases verifier admission.
				tool = "verify_rotation_attestation"
			}
			if test.mcp {
				path = "/mcp"
				if !test.verify {
					body = `{"profileId":"dev","plaintext":"synthetic"}`
				}
				body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + body + `,` + mcpMeta + `}}`
				headers.Set("Accept", "application/json, text/event-stream")
				headers.Set("MCP-Protocol-Version", mcpProtocolVersion)
				headers.Set("Mcp-Method", "tools/call")
				headers.Set("Mcp-Name", tool)
			}
			if test.native == "bearer" {
				var issuer *bearerIssuerFixture
				handler, issuer, _ = bearerHTTPFixtureWithMCP(t, test.mcp)
				headers.Set("Authorization", "Bearer "+issuer.token(t, "https://vaultsmith.example.test", vaultservice.ScopeEncrypt))
			} else if test.native == "session" {
				sessionHandler, authenticator, authCfg, _, _ := nativeHTTPFixture(t)
				handler = sessionHandler
				sessionToken := seedNativeSession(t, authenticator)
				// Bootstrap through the same real server below, including its native writer.
				headers.Set("Cookie", (&http.Cookie{Name: authCfg.Session.CookieName, Value: sessionToken}).String())
				cfg = authCfg
			}
			done := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), uploadApplicationTimeout)
				defer cancel()
				handler.ServeHTTP(w, r.WithContext(ctx))
				if r.Header.Get("X-Test-Stalled-Upload") == "true" {
					close(done)
				}
			}))
			server.Config.ReadTimeout = uploadSocketTimeout
			server.Start()
			defer server.Close()
			server.Client().Timeout = uploadCompletionBudget
			inUse := admission.InUse
			capacity := admission.Capacity()
			if test.native != "" {
				inUse = func() int { return uploadMetric(t, server, "vaultsmith_operation_admission_in_use") }
				capacity = uploadMetric(t, server, "vaultsmith_operation_admission_capacity")
			}
			if test.native == "session" {
				request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/session", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Cookie", headers.Get("Cookie"))
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatalf("session bootstrap failed: %T", err)
				}
				var session sessionResponse
				err = json.NewDecoder(response.Body).Decode(&session)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || !session.Authenticated {
					t.Fatalf("session bootstrap status=%d decode_error=%v authenticated=%v", response.StatusCode, err != nil, session.Authenticated)
				}
				for _, cookie := range response.Cookies() {
					if cookie.Name == csrfCookieName(cfg) {
						headers.Set("Cookie", headers.Get("Cookie")+"; "+(&http.Cookie{Name: cookie.Name, Value: cookie.Value}).String())
					}
				}
				headers.Set(csrfHeaderName, session.CSRFToken)
				headers.Set("Origin", cfg.OIDC.PublicBaseURL)
			}
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatalf("loopback dial failed: %T", err)
			}
			defer conn.Close()
			reader := bufio.NewReader(conn)
			controlStarted := time.Now()
			writeUpload(t, conn, path, headers, body, len(body))
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("control response budget=%s elapsed=%s transport_error=%T", uploadCompletionBudget, time.Since(controlStarted), err)
			}
			controlStatus := response.StatusCode
			var control struct {
				VaultText string
				Result    struct {
					IsError           bool
					StructuredContent struct{ VaultText string }
				}
			}
			err = json.NewDecoder(response.Body).Decode(&control)
			response.Body.Close()
			wantControl := http.StatusOK
			if test.verify && !test.mcp {
				wantControl = http.StatusBadRequest
			}
			if err != nil || controlStatus != wantControl || inUse() != 0 {
				t.Fatalf("completed control status=%d in_use=%d, want %d/0", controlStatus, inUse(), wantControl)
			}
			if !test.verify && control.VaultText == "" && (control.Result.IsError || control.Result.StructuredContent.VaultText == "") {
				t.Fatal("completed control did not produce an encryption result")
			}
			t.Logf("application_deadline=%s socket_timeout=%s completion_tripwire=%s capacity=%d control_elapsed=%s control_status=%d", uploadApplicationTimeout, uploadSocketTimeout, uploadCompletionBudget, capacity, time.Since(controlStarted), controlStatus)
			// Let the previous application deadline pass, then reuse the connection.
			time.Sleep(2 * uploadApplicationTimeout)
			headers.Set("X-Test-Stalled-Upload", "true")
			started := time.Now()
			writeUpload(t, conn, path, headers, body, 1)
			for inUse() == 0 && time.Since(started) < uploadApplicationTimeout {
				time.Sleep(time.Millisecond)
			}
			if observed := inUse(); observed != 1 {
				t.Fatalf("admitted upload in_use=%d elapsed=%s, want 1 before application_deadline=%s", observed, time.Since(started), uploadApplicationTimeout)
			}
			if otherAdmission != nil && otherAdmission.InUse() != 0 {
				t.Fatal("verification upload consumed operation admission")
			}
			response, err = http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("partial upload response budget=%s elapsed=%s in_use=%d transport_error=%T; socket_timeout=%s; investigate retained read before revising tripwire", uploadCompletionBudget, time.Since(started), inUse(), err, uploadSocketTimeout)
			}
			var result struct {
				Error struct{ Code string }
			}
			err = json.NewDecoder(response.Body).Decode(&result)
			response.Body.Close()
			select {
			case <-done:
			case <-time.After(uploadCompletionBudget):
				t.Fatalf("handler completion budget=%s exceeded; elapsed=%s in_use=%d", uploadCompletionBudget, time.Since(started), inUse())
			}
			elapsed := time.Since(started)
			restored := inUse()
			t.Logf("partial_upload_elapsed=%s status=%d code=%s admitted_slots=1 restored_in_use=%d", elapsed, response.StatusCode, result.Error.Code, restored)
			if err != nil || response.StatusCode != http.StatusServiceUnavailable || result.Error.Code != "temporarily_unavailable" || restored != 0 || elapsed >= uploadCompletionBudget {
				t.Fatalf("upload deadline failed: elapsed=%s budget=%s status=%d code=%s decode_error=%v in_use=%d", elapsed, uploadCompletionBudget, response.StatusCode, result.Error.Code, err != nil, restored)
			}
			// A separate completed request proves capacity is usable, not just reported free.
			followup, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			followup.Header = headers.Clone()
			followup.Header.Del("X-Test-Stalled-Upload")
			response, err = server.Client().Do(followup)
			if err != nil {
				t.Fatalf("restored-capacity control failed: %T", err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != wantControl || inUse() != 0 {
				t.Fatalf("restored-capacity status=%d in_use=%d, want %d/0", response.StatusCode, inUse(), wantControl)
			}
		})
	}
}

func TestHTTP2UploadApplicationDeadline(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.AuthConfig{Mode: config.AuthModeOff}
	handler := WrapSecurity(NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{Admission: admission}), cfg)
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), uploadApplicationTimeout)
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
		close(done)
	}))
	server.EnableHTTP2 = true
	server.Config.ReadTimeout = uploadSocketTimeout
	server.StartTLS()
	defer server.Close()
	server.Client().Timeout = uploadCompletionBudget
	reader, writer := io.Pipe()
	defer reader.Close()
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = writer.Write([]byte("{"))
	}()
	defer func() {
		writer.Close()
		<-written
	}()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/profiles/dev/encrypt", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(`{"plaintext":"synthetic"}`))
	started := time.Now()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("HTTP/2 response budget=%s elapsed=%s in_use=%d transport_error=%T", uploadCompletionBudget, time.Since(started), admission.InUse(), err)
	}
	defer response.Body.Close()
	var result struct{ Error struct{ Code string } }
	err = json.NewDecoder(response.Body).Decode(&result)
	select {
	case <-done:
	case <-time.After(uploadCompletionBudget):
		t.Fatalf("HTTP/2 handler completion budget=%s exceeded; in_use=%d", uploadCompletionBudget, admission.InUse())
	}
	t.Logf("HTTP/2 application_deadline=%s socket_timeout=%s elapsed=%s status=%d code=%s restored_in_use=%d", uploadApplicationTimeout, uploadSocketTimeout, time.Since(started), response.StatusCode, result.Error.Code, admission.InUse())
	if response.ProtoMajor != 2 || err != nil || response.StatusCode != http.StatusServiceUnavailable || result.Error.Code != "temporarily_unavailable" || admission.InUse() != 0 {
		t.Fatalf("HTTP/2 deadline contract: protocol=%d status=%d code=%s decode_error=%v in_use=%d", response.ProtoMajor, response.StatusCode, result.Error.Code, err != nil, admission.InUse())
	}
}

type slowSessionStore struct {
	scs.Store
	delay time.Duration
}

func (s slowSessionStore) Find(token string) ([]byte, bool, error) {
	time.Sleep(s.delay)
	return s.Store.Find(token)
}

func TestNativeUploadPreservesSocketReadDeadline(t *testing.T) {
	const socketTimeout = 300 * time.Millisecond
	const applicationTimeout = 350 * time.Millisecond
	const storeDelay = 150 * time.Millisecond
	handler, authenticator, cfg, _, _ := nativeHTTPFixture(t)
	sessionToken := seedNativeSession(t, authenticator)
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ctx, cancel := context.WithTimeout(r.Context(), applicationTimeout)
			defer cancel()
			handler.ServeHTTP(w, r.WithContext(ctx))
			close(done)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	server.Config.ReadTimeout = socketTimeout
	server.Start()
	defer server.Close()
	server.Client().Timeout = uploadCompletionBudget
	headers := http.Header{"Content-Type": {"application/json"}}
	headers.Set("Cookie", (&http.Cookie{Name: cfg.Session.CookieName, Value: sessionToken}).String())
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", headers.Get("Cookie"))
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("bootstrap transport error=%T", err)
	}
	var session sessionResponse
	err = json.NewDecoder(response.Body).Decode(&session)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !session.Authenticated {
		t.Fatalf("bootstrap status=%d decode_error=%v authenticated=%v", response.StatusCode, err != nil, session.Authenticated)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == csrfCookieName(cfg) {
			headers.Set("Cookie", headers.Get("Cookie")+"; "+(&http.Cookie{Name: cookie.Name, Value: cookie.Value}).String())
		}
	}
	headers.Set(csrfHeaderName, session.CSRFToken)
	headers.Set("Origin", cfg.OIDC.PublicBaseURL)
	authenticator.Sessions.Store = slowSessionStore{Store: authenticator.Sessions.Store, delay: storeDelay}
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial error=%T", err)
	}
	defer conn.Close()
	started := time.Now()
	writeUpload(t, conn, "/api/v1/profiles/dev/encrypt", headers, `{"plaintext":"synthetic"}`, 1)
	for uploadMetric(t, server, "vaultsmith_operation_admission_in_use") == 0 && time.Since(started) < socketTimeout {
		time.Sleep(time.Millisecond)
	}
	admitted := uploadMetric(t, server, "vaultsmith_operation_admission_in_use")
	if admitted != 1 {
		t.Fatalf("not admitted before socket bound: in_use=%d elapsed=%s", admitted, time.Since(started))
	}
	response, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response transport error=%T elapsed=%s", err, time.Since(started))
	}
	var result struct{ Error struct{ Code string } }
	err = json.NewDecoder(response.Body).Decode(&result)
	response.Body.Close()
	select {
	case <-done:
	case <-time.After(uploadCompletionBudget):
		t.Fatalf("completion budget=%s exceeded", uploadCompletionBudget)
	}
	elapsed := time.Since(started)
	restored := uploadMetric(t, server, "vaultsmith_operation_admission_in_use")
	t.Logf("socket_timeout=%s parent_application_deadline=%s session_find_delay=%s elapsed=%s status=%d code=%s held_slots=%d restored_in_use=%d", socketTimeout, applicationTimeout, storeDelay, elapsed, response.StatusCode, result.Error.Code, admitted, restored)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || result.Error.Code != "temporarily_unavailable" || restored != 0 {
		t.Fatalf("response contract failed: status=%d code=%s decode_error=%v in_use=%d", response.StatusCode, result.Error.Code, err != nil, restored)
	}
	// The initial real-socket repro completed at 352ms despite a 300ms bound.
	// Normal fixture scheduling costs only a few ms; the midpoint distinguishes
	// socket expiry from the extended app limit without resizing either budget.
	tripwire := socketTimeout + (applicationTimeout-socketTimeout)/2
	if elapsed >= tripwire {
		t.Fatalf("socket bound extended: configured_socket=%s observed=%s midpoint_tripwire=%s; preserve the original socket deadline", socketTimeout, elapsed, tripwire)
	}
}

type opaqueUploadResponseWriter struct{ http.ResponseWriter }

func TestUploadDeadlineRequiresTransportSupport(t *testing.T) {
	admission, err := vaultservice.NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.AuthConfig{Mode: config.AuthModeOff}
	handler := WrapSecurity(NewWithDependencies([]Profile{{ID: "dev", Label: "Development"}}, &fakeExecutor{}, Dependencies{Admission: admission}), cfg)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(opaqueUploadResponseWriter{w}, r)
	}))
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/api/v1/profiles/dev/encrypt", "application/json", strings.NewReader(`{"plaintext":"synthetic"}`))
	if err != nil {
		t.Fatalf("unsupported transport response failed: %T", err)
	}
	defer response.Body.Close()
	var result struct{ Error struct{ Code string } }
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || result.Error.Code != "temporarily_unavailable" || admission.InUse() != 0 {
		t.Fatalf("unsupported transport must fail before admission: status=%d code=%s decode_error=%v in_use=%d", response.StatusCode, result.Error.Code, err != nil, admission.InUse())
	}
}

func writeUpload(t *testing.T, conn net.Conn, path string, headers http.Header, body string, sentBytes int) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(uploadCompletionBudget)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n", path, len(body)); err != nil {
		t.Fatalf("upload headers failed: %T", err)
	}
	if err := headers.Write(conn); err != nil {
		t.Fatalf("upload headers failed: %T", err)
	}
	if _, err := io.WriteString(conn, "\r\n"+body[:sentBytes]); err != nil {
		t.Fatalf("upload write failed: %T", err)
	}
}

func uploadMetric(t *testing.T, server *httptest.Server, name string) int {
	t.Helper()
	response, err := server.Client().Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request failed: %T", err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		var metric string
		var value int
		if _, err := fmt.Sscanf(scanner.Text(), "%s %d", &metric, &value); err == nil && metric == name {
			return value
		}
	}
	t.Fatalf("metric %s missing; status=%d scan_error=%v", name, response.StatusCode, scanner.Err() != nil)
	return 0
}
