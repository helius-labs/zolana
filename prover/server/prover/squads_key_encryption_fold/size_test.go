package squads_key_encryption_fold

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
)

// Compiled against the real key-encryption circuit, so these are the counts
// keygen pays. Pinned because setup memory and time scale with them.
//
// Outer cost follows the inner public-input and commitment counts, not the
// inner circuit size, so a wider leg does not widen the fold.
func TestFoldConstraintCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	want := map[uint32]int{2: 2583619, 3: 3776084}
	const keysPerLeg = 3

	inner, err := InnerSystem(Params{KeysPerLeg: keysPerLeg, Legs: MinLegs})
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}
	_, innerVk, err := groth16.Setup(inner)
	if err != nil {
		t.Fatalf("setup inner: %v", err)
	}

	previous := 0
	for _, legs := range []uint32{2, 3} {
		ccs, err := R1CSFold(Params{KeysPerLeg: keysPerLeg, Legs: legs}, inner, innerVk)
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
