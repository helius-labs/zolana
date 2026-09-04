package gadget

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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
