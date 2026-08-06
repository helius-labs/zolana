package merge_chain

import (
	"testing"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// Compiled against the real merge circuit, so these are the counts keygen pays.
// Pinned because setup memory and time scale with them. Outer cost follows the
// inner public-input and commitment counts plus the openings and cross-leg
// checks a chain adds, not the inner circuit size.
func TestChainConstraintCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	want := map[string]int{"1_1": 1499221, "2_1": 2215367}

	inner, err := InnerSystem()
	if err != nil {
		t.Fatalf("compile merge: %v", err)
	}
	_, innerVk, err := groth16.Setup(inner)
	if err != nil {
		t.Fatalf("setup merge: %v", err)
	}

	for _, levels := range [][]int{{1, 1}, {2, 1}} {
		p := Params{Levels: levels}
		ccs, err := R1CSMergeChain(p, inner, innerVk)
		if err != nil {
			t.Fatalf("compile chain %v: %v", levels, err)
		}
		shape, err := p.Shape()
		if err != nil {
			t.Fatalf("shape %v: %v", levels, err)
		}
		name := common.MergeChainLevelName(p.Levels32())
		count := ccs.GetNbConstraints()
		if count != want[name] {
			t.Errorf("%s is %d constraints, want %d", name, count, want[name])
		}
		t.Logf("%s: %d legs, %d tree inputs, %d constraints",
			name, shape.Legs(), shape.TreeInputs(), count)
	}
}
