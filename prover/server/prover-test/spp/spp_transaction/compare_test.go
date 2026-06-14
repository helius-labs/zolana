package spptransaction

import (
	"light/light-prover/circuits/gadget"
	"math/big"
	"testing"

	"light/light-prover/prover-test/poseidon"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

// isLessCircuit exercises the full-field comparator alone, so its constraints
// (and the alias-bits hint override below) target exactly CanonicalLimbs +
// IsLessLimbs.
type isLessCircuit struct {
	A    frontend.Variable
	B    frontend.Variable
	Want frontend.Variable `gnark:",public"`
}

func (c *isLessCircuit) Define(api frontend.API) error {
	a := gadget.CanonicalLimbs(api, c.A)
	b := gadget.CanonicalLimbs(api, c.B)
	api.AssertIsEqual(gadget.IsLessLimbs(api, a, b), c.Want)
	return nil
}

func TestFullFieldCompareVectors(t *testing.T) {
	assert := test.NewAssert(t)
	pMinus1 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	pMinus2 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(2))
	limbSplit := new(big.Int).Lsh(big.NewInt(1), 127)

	cases := []struct {
		name string
		a, b *big.Int
		want int64
	}{
		{"small a<b", big.NewInt(1), big.NewInt(2), 1},
		{"small a>b", big.NewInt(2), big.NewInt(1), 0},
		{"equal", big.NewInt(7), big.NewInt(7), 0},
		{"zero vs max", big.NewInt(0), pMinus1, 1},
		// The case a single 2^N-offset decomposition gets wrong: a near p and
		// b small wrap a + 2^N - b past p, falsely decomposing as a < b.
		{"a near p, b small", pMinus1, big.NewInt(1), 0},
		{"adjacent at the top", pMinus2, pMinus1, 1},
		{"same hi limb, lo decides", new(big.Int).Add(limbSplit, big.NewInt(3)), new(big.Int).Add(limbSplit, big.NewInt(7)), 1},
		{"hi limb beats larger lo limb", new(big.Int).Sub(limbSplit, big.NewInt(1)), limbSplit, 1},
		{"hi limb beats larger lo limb, reversed", limbSplit, new(big.Int).Sub(limbSplit, big.NewInt(1)), 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assignment := &isLessCircuit{A: tc.a, B: tc.b, Want: big.NewInt(tc.want)}
			assert.SolvingSucceeded(&isLessCircuit{}, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

// A forged "a < b" for a near p must not prove: this is the wrap-around that
// makes narrow-domain offset comparators unsound on full-field values, and in
// the nullifier tree it would be a forged non-inclusion (double spend).
func TestFullFieldCompareRejectsWrapAroundForgery(t *testing.T) {
	assert := test.NewAssert(t)
	pMinus1 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	assignment := &isLessCircuit{A: pMinus1, B: big.NewInt(1), Want: big.NewInt(1)}
	assert.SolvingFailed(&isLessCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestFullFieldCompareRejectsAliasBits pins the canonical (< p) decomposition
// inside CanonicalLimbs: presenting the bits of x+p (the same field element
// with different limbs) must not solve. The nBits hint is overridden to emit
// the alias bits for x's decomposition only; Want is set to the verdict the
// alias limbs produce, so every other constraint is satisfied and the
// full-width ToBinary's modulus check is the sole constraint left to reject.
// If CanonicalLimbs ever drops the full-width decomposition, the alias solves
// and this assertion catches the regression.
func TestFullFieldCompareRejectsAliasBits(t *testing.T) {
	assert := test.NewAssert(t)

	// x + p must fit the 254-bit decomposition for the alias to be encodable.
	x := new(big.Int).Lsh(big.NewInt(0x9abcdef), 220)
	if new(big.Int).Add(x, poseidon.Modulus).BitLen() > 254 {
		t.Fatalf("x+p must fit 254 bits, got %d", new(big.Int).Add(x, poseidon.Modulus).BitLen())
	}
	b := new(big.Int).Add(x, big.NewInt(1))
	// Honest verdict: x < x+1 -> 1. Alias verdict: x+p > x+1 -> 0. Want the
	// alias verdict so only the modulus check can reject.
	want := big.NewInt(0)

	// nBits is GetHints()[1] (order: ithBit, nBits, nTrits). Alias only x's
	// decomposition; every other ToBinary in the circuit stays honest.
	nBitsID := solver.GetHintID(gnarkbits.GetHints()[1])
	aliasBitsHint := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		v := inputs[0]
		if v.Cmp(x) == 0 {
			v = new(big.Int).Add(v, field)
		}
		for i := range outputs {
			outputs[i].SetUint64(uint64(v.Bit(i)))
		}
		return nil
	}

	assignment := &isLessCircuit{A: x, B: b, Want: want}
	assert.SolvingFailed(
		&isLessCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.OverrideHint(nBitsID, aliasBitsHint)),
	)
}
