package custom_ring

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const goldenDigests = "testdata/witness.sha256"

// The fixtures are frozen request bytes every circuit accepts; a decoder change
// must assign the recorded witness, and UPDATE_RING_GOLDENS=1 rewrites only the digests.
func TestGoldenRequestsAssignTheRecordedWitness(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	digests := map[string]string{}
	systems := map[common.CircuitType]constraint.ConstraintSystem{}
	for _, file := range files {
		name := filepath.Base(file)
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err != nil {
			t.Fatal(err)
		}
		assignment := goldenAssignment(t, meta.CircuitType, payload)
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		encoded, err := witness.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		digests[name] = hex.EncodeToString(digest[:])
		cs := systems[meta.CircuitType]
		if cs == nil {
			cs = compileRing(t, meta.CircuitType)
			systems[meta.CircuitType] = cs
		}
		if _, err := cs.Solve(witness); err != nil {
			t.Errorf("%s does not solve: %v", name, err)
		}
	}
	if os.Getenv("UPDATE_RING_GOLDENS") != "" {
		writeDigests(t, digests)
		return
	}
	want := readDigests(t)
	if len(want) != len(digests) {
		t.Fatalf("%d fixtures against %d digests", len(digests), len(want))
	}
	for name, digest := range digests {
		if want[name] != digest {
			t.Errorf("%s assigns a different witness", name)
		}
	}
}

func goldenAssignment(t *testing.T, circuit common.CircuitType, payload []byte) frontend.Circuit {
	t.Helper()
	assignment, err := Decode(circuit, payload)
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	return assignment
}

func readDigests(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(goldenDigests)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digests := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		digest, name, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("malformed digest line %q", scanner.Text())
		}
		digests[name] = digest
	}
	return digests
}

func writeDigests(t *testing.T, digests map[string]string) {
	t.Helper()
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "%s  %s\n", digests[name], name)
	}
	if err := os.WriteFile(goldenDigests, []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
