package squadskeyencryption_test

import (
	"testing"

	. "zolana/prover/circuits/squads/key_encryption"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestKeyEncryptionConstraintCountStable pins every supported key count. These
// keys are local and kept across runs, so a silent change here leaves each
// machine holding a key for a circuit that no longer exists, and the folds
// compiled against it.
func TestKeyEncryptionConstraintCountStable(t *testing.T) {
	want := map[int]int{1: 459859, 2: 581728, 3: 703592}
	for numKeys := 1; numKeys <= 3; numKeys++ {
		circuit := NewKeyEncryptionCircuit(numKeys)
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatalf("compile squads_key_encryption circuit (%d keys): %v", numKeys, err)
		}
		if got := ccs.GetNbConstraints(); got != want[numKeys] {
			t.Errorf("%d keys is %d constraints, want %d", numKeys, got, want[numKeys])
		}
	}
}
