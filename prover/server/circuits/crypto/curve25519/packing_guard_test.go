package curve25519

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// Three 127-bit limbs pack or split into native values at or above 2^254.
var wideLayout = nonnative.Layout{NbLimbs: 3, LimbBits: 127, PieceBits: 10}

type wideLayoutCircuit struct {
	A, B [3]frontend.Variable
	Row  frontend.Variable
	Mode string `gnark:"-"`
}

func (c *wideLayoutCircuit) Define(api frontend.API) error {
	f := nonnative.NewFor(api, Prime(), wideLayout)
	a := f.Bounded(c.A[:], f.ReducedWidths())
	switch c.Mode {
	case "select":
		SelectConstant(api, f, []frontend.Variable{c.Row}, []frontend.Variable{1}, 3, func(int) *big.Int { return big.NewInt(1) })
	case "pack":
		PackCoordinate(api, f, a, 2)
	case "distinct":
		AssertDistinct(api, f, a, f.Bounded(c.B[:], f.ReducedWidths()))
	}
	return nil
}

func TestWideLayoutsRejectNativeWraparound(t *testing.T) {
	for mode, want := range map[string]string{
		"select":   "packed group exceeds the native field",
		"pack":     "packed group exceeds the native field",
		"distinct": "packed halves can wrap the native field",
	} {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &wideLayoutCircuit{Mode: mode})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", mode, err)
		}
	}
}
