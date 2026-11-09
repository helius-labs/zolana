package aes

import (
	"os/exec"
	"strings"
	"testing"
)

// gnark does not seal a committed logderivlookup table, so only this sealed adapter may build one.
func TestOnlyTheSealedAdapterImportsGnarkLookups(t *testing.T) {
	const gnarkLookup = "github.com/consensys/gnark/std/lookup/logderivlookup"
	const adapter = "github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	// Three levels up is the module root, so the scan covers the prover and server packages too.
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "../../../...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if !strings.Contains(" "+line+" ", " "+gnarkLookup+" ") {
			continue
		}
		if fields[0] != adapter {
			t.Errorf("%s imports %s without the AES seal", fields[0], gnarkLookup)
		}
		seen = seen || fields[0] == adapter
	}
	if !seen {
		t.Fatalf("go list did not report the adapter importing %s", gnarkLookup)
	}
}
