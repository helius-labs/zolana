package backend

import (
	"os/exec"
	"strings"
	"testing"
)

// Library packages take their prover from the caller: depending on this
// package would put its aeglos build into every consumer's module graph.
func TestLibraryPackagesDoNotImportTheBackend(t *testing.T) {
	const backend = "github.com/helius-labs/zolana/prover/server/prover/backend"
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}} {{join .Deps \" \"}}", "../...", "../../circuits/...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if strings.HasPrefix(fields[0], backend) {
			continue
		}
		for _, dependency := range fields[1:] {
			if dependency == backend {
				t.Errorf("%s depends on %s", fields[0], backend)
			}
		}
	}
}
