// Tested invariants:
//
//  1. Rational reconstruction returns two halves below 2^128 that satisfy the
//     reconstruction relation, at boundary and random scalars.
//  2. The top radix-four digit of a half is bounded to one bit.
//  3. Key agreement accepts non-Boolean digit constituents that preserve each
//     digit and rejects radix carries that preserve the scalar but exceed a
//     digit bound.
package emcurve

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// Invariant 1: Rational reconstruction returns halves below 2^128.
func TestReconstructionHalvesFit128Bits(t *testing.T) {
	n := GroupOrder()
	root := new(big.Int).Sqrt(n)
	bound := pow2(halfScalarBits - 1)
	// The half-GCD invariant is r0·|t1| + r1·|t0| = n. Its stopping rule gives
	// r1 < floor(sqrt(n)) <= r0, hence |t1| <= n/floor(sqrt(n)) < 2^128.
	if new(big.Int).Mul(bound, root).Cmp(n) <= 0 {
		t.Fatal("the P-256 denominator bound is not below 2^128")
	}
	values := []*big.Int{
		new(big.Int), big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)), n, new(big.Int).Add(n, big.NewInt(1)),
		new(big.Int).Sub(root, big.NewInt(1)), root, new(big.Int).Add(root, big.NewInt(1)),
		new(big.Int).Sub(bound, big.NewInt(1)), bound, new(big.Int).Add(bound, big.NewInt(1)),
	}
	rng := rand.New(rand.NewSource(128))
	for i := 0; i < 256; i++ {
		values = append(values, new(big.Int).Rand(rng, n))
	}
	reconstructor := lattice.NewReconstructor(n)
	for _, s := range values {
		pair := reconstructor.RationalReconstruct(s)
		if pair[0].Sign() < 0 || pair[0].Cmp(bound) >= 0 || new(big.Int).Abs(pair[1]).Cmp(bound) >= 0 || pair[1].Sign() == 0 {
			t.Fatalf("scalar %x: reconstruction exceeds the 128-bit bounds", s)
		}
		if new(big.Int).Mod(new(big.Int).Sub(pair[0], new(big.Int).Mul(s, pair[1])), n).Sign() != 0 {
			t.Fatalf("scalar %x: reconstruction relation failed", s)
		}
	}
}

// Invariant 2: The top radix-four digit is bounded to one bit.
func TestRadixHalfTopDigitIsBoundedToOneBit(t *testing.T) {
	cs := compile(t, &radixHalfBoundCircuit{})
	for _, row := range []struct {
		low, high int
		accept    bool
	}{{0, 0, true}, {1, 0, true}, {3, -1, true}, {2, 0, false}, {0, 1, false}} {
		w := &radixHalfBoundCircuit{}
		for i := range w.Bits {
			w.Bits[i] = 0
		}
		w.Bits[halfScalarBits-2], w.Bits[halfScalarBits-1] = row.low, row.high
		w.Want = new(big.Int).Mul(big.NewInt(int64(row.low+2*row.high)), pow2(halfScalarBits-2))
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("top constituents %d,%d: accept=%v err=%v", row.low, row.high, row.accept, err)
		}
	}
}

// Invariant 3: Key agreement bounds every radix-four digit.
func TestAgreeKeyRadixFourDigitBounds(t *testing.T) {
	cs := compile(t, &agreeKeyCircuit{})
	honest := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
	for _, row := range []struct {
		name   string
		change func(q *big.Int, outputs []*big.Int)
		accept bool
	}{
		{
			"same digit with non-Boolean constituents",
			func(q *big.Int, outputs []*big.Int) {
				// The circuit consumes b1 + 2·b2, which this preserves.
				outputs[2].Add(outputs[2], big.NewInt(2)).Mod(outputs[2], q)
				outputs[3].Sub(outputs[3], big.NewInt(1)).Mod(outputs[3], q)
			}, true,
		},
		{
			"same top digit with non-Boolean constituents",
			func(q *big.Int, outputs []*big.Int) {
				outputs[halfScalarBits-1].Add(outputs[halfScalarBits-1], big.NewInt(2)).Mod(outputs[halfScalarBits-1], q)
				outputs[halfScalarBits].Sub(outputs[halfScalarBits], big.NewInt(1)).Mod(outputs[halfScalarBits], q)
			}, true,
		},
		{
			"radix carry preserves the scalar but exceeds the digit bound",
			func(q *big.Int, outputs []*big.Int) {
				outputs[2].Add(outputs[2], big.NewInt(4)).Mod(outputs[2], q)
				outputs[4].Sub(outputs[4], big.NewInt(1)).Mod(outputs[4], q)
			}, false,
		},
		{
			"low bit carry preserves the scalar but exceeds the Boolean bound",
			func(q *big.Int, outputs []*big.Int) {
				outputs[1].Add(outputs[1], big.NewInt(2)).Mod(outputs[1], q)
				outputs[2].Sub(outputs[2], big.NewInt(1)).Mod(outputs[2], q)
			}, false,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			called := false
			override := solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				called = true
				if err := p256DecomposeScalarHint(q, inputs, outputs); err != nil {
					return err
				}
				row.change(q, outputs)
				return nil
			})
			err := solveAgreeKey(t, cs, honest, override)
			if !called {
				t.Fatal("the decomposition override did not run")
			}
			if (err == nil) != row.accept {
				t.Fatalf("accept=%v: %v", row.accept, err)
			}
		})
	}
}

// Test circuits and shared helpers.

type radixHalfBoundCircuit struct {
	Bits [halfScalarBits]frontend.Variable
	Want frontend.Variable `gnark:",public"`
}

func (c *radixHalfBoundCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	digits := cv.radixFourDigits(c.Bits[:])
	half := cv.scalarFromRadixFour(c.Bits[0], digits)
	api.AssertIsEqual(cv.nativeValue(half), c.Want)
	return nil
}
