package policy

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// InlineCount is the committed prefix length. Values after it are canonical
// zero padding and cannot extend the membership set used by evaluation.
func TestUncommittedInlinePaddingCannotExtendAllowlist(t *testing.T) {
	cs := testConstraintSystem(t)

	// The committed allowlist holds one asset, 0xe5, that is not transferred.
	// The transaction moves 0xd4 (defaultFixture.transferred).
	f := defaultFixture()
	f.inlineAsset = fill(0xe5)

	// Control: with inline_count = 1 and no padding, the transferred asset is
	// uncovered and the circuit rejects.
	control, err := frontend.NewWitness(buildAssignment(t, f), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(control); err == nil {
		t.Fatal("control: the transferred asset is not in the committed allowlist, want rejection")
	}

	// Parking the transferred asset in slot 1 while inline_count stays 1 must
	// fail: the slot is outside the committed prefix.
	c := buildAssignment(t, f)
	c.InlineAssets[1] = pkField(t, f.transferred)
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new padded witness: %v", err)
	}
	if err := cs.IsSolved(witness); err == nil {
		t.Fatal("non-zero inline padding satisfied the circuit")
	}
}
