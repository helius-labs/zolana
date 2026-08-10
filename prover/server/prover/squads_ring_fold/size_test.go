package squads_zone_fold

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
)

// Compiled against the real zone circuit, so these are the counts keygen pays.
// Pinned because setup memory and time scale with them.
//
// Outer cost follows the inner public-input and commitment counts, not the
// inner circuit size, so a wider leg shape does not widen the fold.
func TestFoldConstraintCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	want := map[uint32]int{2: 2576895, 3: 3766715}
	shape := Params{NInputs: 2, NOutputs: 2, Legs: MinLegs}

	inner, err := InnerSystem(shape)
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}
	_, innerVk, err := groth16.Setup(inner)
	if err != nil {
		t.Fatalf("setup inner: %v", err)
	}

	previous := 0
	for _, legs := range []uint32{2, 3} {
		shape.Legs = legs
		ccs, err := R1CSFold(shape, inner, innerVk)
		if err != nil {
			t.Fatalf("compile fold of %d legs: %v", legs, err)
		}
		count := ccs.GetNbConstraints()
		if count != want[legs] {
			t.Errorf("%d legs is %d constraints, want %d", legs, count, want[legs])
		}
		if previous > 0 {
			t.Logf("%d legs: %d constraints, %d per added leg", legs, count, count-previous)
		}
		previous = count
	}
}
