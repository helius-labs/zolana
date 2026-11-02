package nonnative

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// One limb interval ends one past the window that signed() decodes.
type wideLimbCircuit struct {
	Limbs [6]frontend.Variable
	Eval  bool `gnark:"-"`
}

func (c *wideLimbCircuit) Define(api frontend.API) error {
	f := NewFor(api, edProjectionPrime, edProjectionLayout)
	lo, hi := make([]*big.Int, 6), make([]*big.Int, 6)
	for i := range lo {
		lo[i], hi[i] = new(big.Int), new(big.Int)
	}
	hi[0].Rsh(api.Compiler().Field(), 1).Add(hi[0], big.NewInt(1))
	wide := f.WithBounds(c.Limbs[:], lo, hi)
	if c.Eval {
		// A zero partner keeps the product bound at zero, so only the encoder can refuse.
		f.Eval(T(1, wide, f.Const(new(big.Int))))
	} else {
		f.Hint(wideLimbHint, 1, nil, wide)
	}
	return nil
}

func wideLimbHint(q *big.Int, inputs, outputs []*big.Int) error {
	return Unwrap(q, inputs, outputs, func(_ *big.Int, _, _, _ []*big.Int) error { return nil })
}

func TestHintEncodersRejectWideLimbs(t *testing.T) {
	for _, eval := range []bool{false, true} {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &wideLimbCircuit{Eval: eval})
		if err == nil || !strings.Contains(err.Error(), "hint limb exceeds the signed native window") {
			t.Errorf("eval %v: %v", eval, err)
		}
	}
}
