package version

import "fmt"

// These values are replaced by release builds through Go linker flags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
