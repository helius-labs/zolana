package nullifierbatchupdate

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// orderingCircuit exercises assertStrictlyOrdered in isolation so the strict
// low < new < next check can be tested without the surrounding Merkle machinery.
type orderingCircuit struct {
	Lo  frontend.Variable
	Mid frontend.Variable
	Hi  frontend.Variable
}

func (c *orderingCircuit) Define(api frontend.API) error {
	assertStrictlyOrdered(api, c.Lo, c.Mid, c.Hi)
	return nil
}

// TestAssertStrictlyOrderedRejectsFieldWraparound guards against a regression to
// the `lo+1 <= mid` form, which wraps a near-modulus value to a small one and so
// vacuously satisfies the ordering. The "wraps modulus" cases solve under that
// buggy form but must be rejected here.
func TestAssertStrictlyOrderedRejectsFieldWraparound(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()
	maxFr := new(big.Int).Sub(field, big.NewInt(1)) // Fr - 1

	cases := []struct {
		name        string
		lo, mid, hi *big.Int
		ok          bool
	}{
		{"valid ordering", big.NewInt(10), big.NewInt(20), big.NewInt(30), true},
		{"low wraps modulus", maxFr, big.NewInt(20), big.NewInt(30), false},
		{"mid wraps modulus", big.NewInt(10), maxFr, big.NewInt(30), false},
		{"equal lo and mid", big.NewInt(10), big.NewInt(10), big.NewInt(30), false},
		{"out of order", big.NewInt(30), big.NewInt(20), big.NewInt(40), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			witness := &orderingCircuit{Lo: tc.lo, Mid: tc.mid, Hi: tc.hi}
			err := test.IsSolved(&orderingCircuit{}, witness, field)
			if tc.ok {
				assert.NoError(err)
			} else {
				assert.Error(err)
			}
		})
	}
}
