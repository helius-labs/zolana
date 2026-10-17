package custom_ring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// The Rust SDK pins these request bodies byte for byte, so every one must
// decode strictly and assign its circuit.
func TestRustFixturesDecodeAndAssign(t *testing.T) {
	files, err := filepath.Glob("../../../../custom-rings/sdk/tests/fixtures/prover-json/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Rust fixtures: %v", err)
	}
	seen := map[common.CircuitType]bool{}
	for _, file := range files {
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err == nil {
			_, err = Ring(meta.CircuitType)
		}
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(file), err)
		}
		if _, err := Decode(meta.CircuitType, payload); err != nil {
			t.Errorf("%s: %v", filepath.Base(file), err)
		}
		seen[meta.CircuitType] = true
	}
	for _, ring := range RingCircuits {
		if !seen[ring.Type] {
			t.Errorf("no Rust fixture for %s", ring.Type)
		}
	}
}
