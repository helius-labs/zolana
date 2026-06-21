package merge

import (
	"os"
	"testing"

	"zolana/prover/prover/common"
)

// TestReadMergeKeyDispatch validates the server key-load path: ReadSystemFromFile
// must recognize a merge_*.key by name, deserialize it as a TransferProofSystem,
// and tag it MergeCircuitType. Skips when the (gitignored) key is absent.
func TestReadMergeKeyDispatch(t *testing.T) {
	const keyPath = "../../proving-keys/merge_8_1.key"
	if _, err := os.Stat(keyPath); err != nil {
		t.Skipf("merge key not present (%s); run scripts/generate_keys_merge.sh", keyPath)
	}

	system, err := common.ReadSystemFromFile(keyPath)
	if err != nil {
		t.Fatalf("read merge key: %v", err)
	}
	ps, ok := system.(*common.TransferProofSystem)
	if !ok {
		t.Fatalf("expected *TransferProofSystem, got %T", system)
	}
	if ps.CircuitType != common.MergeCircuitType {
		t.Fatalf("circuit type: got %s want %s", ps.CircuitType, common.MergeCircuitType)
	}
	if ps.NInputs != MergeNInputs || ps.NOutputs != MergeNOutputs {
		t.Fatalf("shape: got %dx%d want %dx%d", ps.NInputs, ps.NOutputs, MergeNInputs, MergeNOutputs)
	}
}
