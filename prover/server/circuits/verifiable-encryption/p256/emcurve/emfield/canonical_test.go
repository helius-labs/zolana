// Tested invariants and diagnostics:
//
//  1. Limbwise canonical checks enforce the strict modulus bound.
//  2. The fallback modulus-gap check rejects a forged gap.
package emfield

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Invariant 1: Limbwise canonical checks enforce the strict modulus bound.
func TestPlainAssertCanonicalComparesLimbwise(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) { assertCanonicalComparesLimbwise(t, l.layout) })
	}
}

// Invariant 2: The fallback modulus-gap check rejects a forged gap.
func TestCanonicalModulusGapRejectsForgery(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			circuit := &plainCanonicalCircuit{Lay: l.layout, Mod: p256N}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				value  *big.Int
				accept bool
			}{
				{big.NewInt(0), true},
				{new(big.Int).Sub(p256N, big.NewInt(1)), true},
				{p256N, false},
				{new(big.Int).Sub(pow2(256), big.NewInt(1)), false},
			} {
				witness, _ := frontend.NewWitness(&plainCanonicalCircuit{Lay: l.layout, Mod: p256N, Limbs: plainLimbs(row.value)}, ecc.BN254.ScalarField())
				if err := cs.IsSolved(witness); (err == nil) != row.accept {
					t.Fatalf("value %x: accept=%v err=%v", row.value, row.accept, err)
				}
			}
			forged := solver.OverrideHint(solver.GetHintID(modulusGapHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				gap := new(big.Int).Sub(pow2(256), big.NewInt(1))
				rest := l.layout.writePieces(outputs, gap, l.layout.reducedWidths(256))
				rest[0].SetUint64(1)
				return nil
			})
			expectRejected(t, cs, &plainCanonicalCircuit{Lay: l.layout, Mod: p256N, Limbs: plainLimbs(p256N)}, forged)
		})
	}
}

// Test circuits and shared helpers.

type plainCanonicalCircuit struct {
	Lay   Layout   `gnark:"-"`
	Mod   *big.Int `gnark:"-"`
	Limbs [8]frontend.Variable
}

func (c *plainCanonicalCircuit) Define(api frontend.API) error {
	mod := c.Mod
	if mod == nil {
		mod = p256P
	}
	f := NewFor(api, mod, c.Lay)
	f.AssertCanonical(f.FromLimbs(c.Limbs[:]))
	return nil
}
