package gadget

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

// mixedWidthLessCircuit feeds IsLessLimbs limbs decomposed at different
// widths: a at 4 bits per limb, b at 8. It bypasses CanonicalLimbs on purpose
// to pin that the bounded comparison is sized by the wider operand rather than
// by a alone.
type mixedWidthLessCircuit struct {
	ALo, AHi frontend.Variable
	BLo, BHi frontend.Variable
	Want     frontend.Variable `gnark:",public"`
}

func (c *mixedWidthLessCircuit) Define(api frontend.API) error {
	a := fieldLimbs{lo: c.ALo, hi: c.AHi, loBits: 4, hiBits: 4}
	b := fieldLimbs{lo: c.BLo, hi: c.BHi, loBits: 8, hiBits: 8}
	api.AssertIsEqual(IsLessLimbs(api, a, b), c.Want)
	return nil
}

func TestIsLessLimbsSizesByWiderOperand(t *testing.T) {
	assert := test.NewAssert(t)
	cases := []struct {
		name     string
		aLo, aHi int64
		bLo, bHi int64
		want     int64
	}{
		// b's limbs exceed a's 4-bit width; a 4-bit offset would wrap the
		// difference past 2^5 and leave the circuit unsatisfiable.
		{"wide b hi limb decides", 3, 3, 0, 200, 1},
		{"wide b lo limb breaks tie", 3, 3, 200, 3, 1},
		{"a greater on hi limb", 0, 15, 255, 14, 0},
		{"a greater on lo limb", 15, 3, 14, 3, 0},
		{"equal", 5, 6, 5, 6, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assignment := &mixedWidthLessCircuit{
				ALo: big.NewInt(tc.aLo), AHi: big.NewInt(tc.aHi),
				BLo: big.NewInt(tc.bLo), BHi: big.NewInt(tc.bHi),
				Want: big.NewInt(tc.want),
			}
			assert.SolvingSucceeded(&mixedWidthLessCircuit{}, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

type orderedCircuit struct{ Enabled, Lo, Mid, Hi frontend.Variable }

func (c *orderedCircuit) Define(api frontend.API) error {
	AssertOrderedWhen(api, c.Enabled, c.Lo, c.Mid, c.Hi)
	return nil
}

// The gap partition holds at the field edges and refuses every forged limb split.
func TestOrderedBoundariesAndForgedHints(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &orderedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(w *orderedCircuit, options ...solver.Option) error {
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, options...)
	}
	b := new(big.Int).Lsh(big.NewInt(1), gapLimbBits)
	max := new(big.Int).Sub(q, big.NewInt(1))
	for _, w := range []*orderedCircuit{
		{1, 0, 1, 2}, {1, 0, 1, max},
		{1, new(big.Int).Sub(b, big.NewInt(1)), b, new(big.Int).Add(b, big.NewInt(1))},
		{1, new(big.Int).Sub(max, big.NewInt(2)), new(big.Int).Sub(max, big.NewInt(1)), max},
		{0, max, 0, 0},
	} {
		if err := solve(w); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range []*orderedCircuit{{1, 1, 1, 2}, {1, 0, 2, 2}, {1, max, 0, 1}, {1, 0, max, 1}} {
		if err := solve(w); err == nil {
			t.Fatal("unordered values accepted")
		}
	}
	for _, attack := range []string{"limb carry", "gap alias", "carry overflow"} {
		t.Run(attack, func(t *testing.T) {
			called := false
			forge := func(field *big.Int, in, out []*big.Int) error {
				called = true
				if err := orderedGapsHint(field, in, out); err != nil {
					return err
				}
				switch attack {
				case "limb carry":
					out[0].Add(out[0], b)
					out[1].Sub(out[1], big.NewInt(1))
				case "gap alias":
					alias := new(big.Int).Add(q, big.NewInt(1))
					out[2].And(alias, new(big.Int).Sub(b, big.NewInt(1)))
					out[3].Rsh(alias, gapLimbBits)
				case "carry overflow":
					out[8].Add(out[8], big.NewInt(4))
				}
				return nil
			}
			err := solve(&orderedCircuit{1, 0, 2, 4}, solver.OverrideHint(solver.GetHintID(orderedGapsHint), forge), hintattack.SkipMissingLookupQueries(t))
			if !called {
				t.Fatal("forgery did not run")
			}
			hintattack.RequireConstraintRejection(t, err)
		})
	}
}
