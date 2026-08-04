package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogStartupWarning(t *testing.T) {
	var output bytes.Buffer
	logger := log.New(&output, "", 0)

	logStartupWarning(logger)

	const want = "WARNING: Vaultsmith does not authenticate requests; run it only behind an authenticated private boundary.\n"
	if got := output.String(); got != want {
		t.Fatalf("logStartupWarning() = %q, want %q", got, want)
	}
	if strings.Contains(output.String(), "profile") || strings.Contains(output.String(), "password") {
		t.Fatalf("startup warning contains sensitive configuration terms: %q", output.String())
	}
}
