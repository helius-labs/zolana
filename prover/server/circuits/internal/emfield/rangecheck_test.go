package emfield

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Forged range decomposition and multiplicity hints are rejected.
func TestRangeCheckHintForgeriesAreRejected(t *testing.T) {
	p := edProjectionPrime
	cs := compilePlain(t, p)
	w := plainArithWitness(p, big.NewInt(0x1234_5678), new(big.Int).Sub(p, big.NewInt(7)), big.NewInt(99))
	t.Run("multiplicities", func(t *testing.T) {
		expectRejected(t, cs, w, solver.OverrideHint(solver.GetHintID(countHint), func(q *big.Int, inputs, outputs []*big.Int) error {
			if err := countHint(q, inputs, outputs); err != nil {
				return err
			}
			outputs[0].Add(outputs[0], big.NewInt(1))
			return nil
		}))
	})
	t.Run("decomposition", func(t *testing.T) {
		expectRejected(t, cs, w, solver.OverrideHint(solver.GetHintID(decomposeHighHint), func(q *big.Int, inputs, outputs []*big.Int) error {
			if err := decomposeHighHint(q, inputs, outputs); err != nil {
				return err
			}
			outputs[0].Add(outputs[0], pow2(edProjectionLayout.PieceBits))
			outputs[1].Sub(outputs[1], big.NewInt(1)).Mod(outputs[1], q)
			return nil
		}))
	})
}

// Partial-piece range checks accept their maximum and reject the next value.
func TestPartialPieceRangeCheck(t *testing.T) {
	q := ecc.BN254.ScalarField()
	for _, bits := range []int{3, 8} {
		cs, err := frontend.Compile(q, r1cs.NewBuilder, &smallRangeCircuit{Bits: bits})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct {
			v      *big.Int
			accept bool
		}{
			{big.NewInt(0), true},
			{new(big.Int).Sub(pow2(bits), big.NewInt(1)), true},
			{pow2(bits), false},
			{new(big.Int).Sub(q, big.NewInt(1)), false},
			{new(big.Int).ModInverse(pow2(edProjectionLayout.PieceBits-bits), q), false},
		} {
			w := smallRangeCircuit{Bits: bits}
			for i := range w.V {
				w.V[i] = 1
			}
			w.V[0] = row.v
			witness, _ := frontend.NewWitness(&w, q)
			if err := cs.IsSolved(witness); (err == nil) != row.accept {
				t.Fatalf("bits %d value %x: accept=%v err=%v", bits, row.v, row.accept, err)
			}
		}
	}
}

func init() {
	solver.RegisterHint(inverseHint)
}

func inverseHint(q *big.Int, inputs, outputs []*big.Int) error {
	return Unwrap(q, inputs, outputs, func(mod *big.Int, _, in, out []*big.Int) error {
		out[0].ModInverse(in[0], mod)
		return nil
	})
}

func expectRejected(t *testing.T, cs constraint.ConstraintSystem, w frontend.Circuit, opts ...solver.Option) {
	t.Helper()
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = cs.IsSolved(witness, opts...)
	if err == nil {
		t.Fatal("forged witness accepted")
	}
	if !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("expected a constraint failure, got %v", err)
	}
}

type smallRangeCircuit struct {
	V    [12]frontend.Variable
	Bits int `gnark:"-"`
}

func (c *smallRangeCircuit) Define(api frontend.API) error {
	rc := NewRangeCheckerFor(api, edProjectionLayout.PieceBits)
	for _, v := range c.V {
		rc.Check(v, c.Bits)
	}
	return nil
}

// Deferred callers must not append range checks after the argument was sealed.
type lateRangeCircuit struct{ Value frontend.Variable }

func (c *lateRangeCircuit) Define(api frontend.API) error {
	rc := NewRangeCheckerFor(api, 11)
	api.Compiler().Defer(func(api frontend.API) error { rc.Check(c.Value, 8); return nil })
	return nil
}

func TestLateRangeCheckRejectsCompilation(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lateRangeCircuit{})
	if err == nil || !strings.Contains(err.Error(), "range table already finalized") {
		t.Fatalf("late range check: %v", err)
	}
}

// A composed width at or above the native field bit length wraps and is rejected.
type wideComposeCircuit struct{ Pieces [24]frontend.Variable }

func (c *wideComposeCircuit) Define(api frontend.API) error {
	rc := NewRangeCheckerFor(api, 11)
	rc.Compose(c.Pieces[:], api.Compiler().FieldBitLen())
	return nil
}

func TestComposeRejectsFieldWidth(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &wideComposeCircuit{})
	if err == nil || !strings.Contains(err.Error(), "composed width must stay below the native field bit length") {
		t.Fatalf("wide compose: %v", err)
	}
}
