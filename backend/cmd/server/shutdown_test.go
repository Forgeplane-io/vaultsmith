package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const shutdownHelperEnv = "VAULTSMITH_TEST_SHUTDOWN_HELPER"

func TestShutdownHelper(t *testing.T) {
	if os.Getenv(shutdownHelperEnv) != "1" {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "run completed")
	os.Exit(0)
}

// The harness allows the existing 10-second drain budget plus 15 seconds for
// startup/race instrumentation. Expiry fails the test and kills the child;
// increase only if recorded CI startup times require it.
const shutdownTestBudget = 25 * time.Second

func shutdownCommand(t *testing.T, address, profiles string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTestBudget)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownHelper$")
	command.Env = []string{
		shutdownHelperEnv + "=1", "AUTH_MODE=off", "COOKIE_SECURE=false",
		"HTTP_ADDR=" + address, "VAULT_PROFILES_JSON=" + profiles,
		"VAULT_PASSWORD_DRAIN=synthetic-drain-password",
	}
	output := new(bytes.Buffer)
	command.Stdout, command.Stderr = output, output
	return command, output
}

const shutdownProfiles = `[{"id":"drain","label":"Drain","passwordEnv":"VAULT_PASSWORD_DRAIN"}]`

func TestHTTPShutdownInSubprocess(t *testing.T) {
	for _, completeBody := range []bool{true, false} {
		name := "budget expiry"
		if completeBody {
			name = "successful drain"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			listener.Close()
			command, output := shutdownCommand(t, address, shutdownProfiles)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			})
			// The same overall deadline covers readiness, TCP IO and process exit.
			deadline := time.Now().Add(shutdownTestBudget)
			var connection net.Conn
			for time.Now().Before(deadline) {
				connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("readiness exceeded harness budget %s: %v", shutdownTestBudget, err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			body := `{"profileId":"drain","mode":"encrypt","value":"synthetic-drain-value"}`
			_, err = fmt.Fprintf(connection, "POST /api/v1/operations HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", address, len(body))
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(connection)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusContinue {
				t.Fatalf("admission status = %d, want 100", response.StatusCode)
			}
			if _, err := connection.Write([]byte(body[:1])); err != nil {
				t.Fatal(err)
			}
			t.Log("request admitted (100 Continue); partial body sent")
			started := time.Now()
			if err := command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			t.Log("SIGTERM sent")
			// Listener refusal proves Shutdown has begun; no timing sleep barrier.
			for {
				probe, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if err != nil {
					break
				}
				probe.Close()
				if time.Now().After(deadline) {
					t.Fatalf("listener still accepting after harness budget %s", shutdownTestBudget)
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Log("listener closed; draining started")
			if completeBody {
				if _, err := connection.Write([]byte(body[1:])); err != nil {
					t.Fatalf("body completion during drain: %v", err)
				}
				response, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatalf("response during drain: %v", err)
				}
				var result struct{ Value string }
				err = json.NewDecoder(response.Body).Decode(&result)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || !strings.HasPrefix(result.Value, "$ANSIBLE_VAULT;") {
					t.Fatalf("operation failed: status=%d decode_error=%v (body redacted)", response.StatusCode, err)
				}
				t.Log("completed server operation; successful response received")
			}
			err = command.Wait()
			waited = true
			elapsed := time.Since(started)
			if completeBody {
				if err != nil || !strings.Contains(output.String(), "run completed") {
					t.Fatalf("drain exit: %v; %s", err, output)
				}
			} else if err == nil || !strings.Contains(output.String(), "context deadline exceeded") || elapsed < 10*time.Second {
				t.Fatalf("shutdown budget=10s observed=%s exit=%v output=%s", elapsed, err, output)
			}
			t.Logf("run returned and process exited: elapsed=%s error=%v", elapsed, err)
		})
	}
}

func TestShutdownStartupErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, test := range []struct{ name, profiles, want string }{
		{"configuration", "", "VAULT_PROFILES_JSON is required"},
		{"listener", shutdownProfiles, "address already in use"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, output := shutdownCommand(t, listener.Addr().String(), test.profiles)
			if err := command.Run(); err == nil || !strings.Contains(output.String(), test.want) {
				t.Fatalf("startup exit=%v output=%s; want %s", err, output, test.want)
			}
		})
	}
}
