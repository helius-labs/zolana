package nullifier_fold

import (
	"testing"

	nullifiertree "zolana/prover/prover/nullifier_tree"

	"github.com/consensys/gnark/backend/groth16"
)

// Compiled against the real append circuit, so these are the counts keygen
// pays. Pinned because setup memory and time scale with them.
//
// Outer cost follows the inner public-input and commitment counts, not the
// inner circuit size. The excess over the aggregate is the four openings and
// the two continuity assertions this fold adds.
func TestFoldConstraintCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	want := map[uint32]int{2: 1472103, 3: 2175073}

	inner, err := nullifiertree.R1CSBatchAddressAppend(40, 10)
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}
	_, innerVk, err := groth16.Setup(inner)
	if err != nil {
		t.Fatalf("setup inner: %v", err)
	}

	previous := 0
	for _, run := range []uint32{2, 3} {
		ccs, err := R1CSFold(Params{TreeHeight: 40, BatchSize: 10, Run: run}, inner, innerVk)
		if err != nil {
			t.Fatalf("compile fold run %d: %v", run, err)
		}
		count := ccs.GetNbConstraints()
		if count != want[run] {
			t.Errorf("run %d is %d constraints, want %d", run, count, want[run])
		}
		if previous > 0 {
			t.Logf("run %d: %d constraints, %d per added append", run, count, count-previous)
		}
		previous = count
	}
}
