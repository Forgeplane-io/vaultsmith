package version

import "testing"

func TestString(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = oldVersion, oldCommit, oldBuildDate })

	Version = "0.1.0"
	Commit = "abc123"
	BuildDate = "2026-08-04T00:00:00Z"

	if got, want := String(), "0.1.0 (commit abc123, built 2026-08-04T00:00:00Z)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
