package emfield

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type projectionPairCircuit struct {
	X, Y     [8]frontend.Variable
	Expected [14]frontend.Variable
}

type projectedEvalCircuit struct {
	Negative bool `gnark:"-"`
	X, Y     [8]frontend.Variable
}

func (c *projectedEvalCircuit) Define(api frontend.API) error {
	f := NewFor(api, elliptic.P256().Params().P, projectionLayout)
	x, y := fromLimbs(f, c.X[:]), fromLimbs(f, c.Y[:])
	if c.Negative {
		x = f.Neg(x)
	}
	// Deliberately omit output equality checks: the reduction certificate
	// itself must reject a forged remainder.
	f.EvalProjected(T(1, x, y))
	return nil
}

func TestEvalProjectedRejectsNativeModulusAliases(t *testing.T) {
	q := ecc.BN254.ScalarField()

	for _, negative := range []bool{false, true} {
		c := &projectedEvalCircuit{Negative: negative}
		cs, err := frontend.Compile(q, r1cs.NewBuilder, c)
		if err != nil {
			t.Fatal(err)
		}
		w := &projectedEvalCircuit{X: plainLimbs(big.NewInt(1)), Y: plainLimbs(big.NewInt(2))}
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatal(err)
		}
		for _, shift := range []*big.Int{big.NewInt(1), q} {
			called := false
			override := solver.OverrideHint(solver.GetHintID(PlainCheckHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				called = true
				if err := PlainCheckHint(q, inputs, outputs); err != nil {
					return err
				}
				lay, err := layoutOf(inputs)
				if err != nil {
					return err
				}
				widths := lay.reducedWidths(256)
				r := lay.recomposePieces(outputs, widths)
				r.Add(r, shift)
				lay.writePieces(outputs, r, widths)
				return nil
			})
			if err := cs.IsSolved(witness, override); err == nil {
				t.Fatalf("negative=%v remainder shifted by %s accepted", negative, shift)
			}
			if !called {
				t.Fatal("forged remainder hint did not run")
			}
		}
		// A forged remainder can make the low carry zero while placing the
		// native quotient outside its integer bound. Without that bound,
		// a multiple of q*B^2 is hidden above the checked low coefficients.
		p := elliptic.P256().Params().P
		high := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 64)
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(q, high, remainder)
		badR := new(big.Int).Lsh(remainder, 64)
		badR.Add(badR, quotient)
		if negative {
			badR.Sub(badR, big.NewInt(2))
		} else {
			badR.Add(badR, big.NewInt(2))
		}
		called := false
		override := solver.OverrideHint(solver.GetHintID(PlainCheckHint), func(q *big.Int, inputs, outputs []*big.Int) error {
			called = true
			if err := PlainCheckHint(q, inputs, outputs); err != nil {
				return err
			}
			lay, err := layoutOf(inputs)
			if err != nil {
				return err
			}
			lay.writePieces(outputs, badR, lay.reducedWidths(256))
			return nil
		})
		if err := cs.IsSolved(witness, override); err == nil {
			t.Fatalf("negative=%v unbounded quotient alias accepted", negative)
		}
		if !called {
			t.Fatal("unbounded quotient remainder hint did not run")
		}
	}

}

func (c *projectionPairCircuit) Define(api frontend.API) error {
	f := NewFor(api, elliptic.P256().Params().P, projectionLayout)
	// Test the native polynomial tensor over all of Fq. Input limb bounds
	// are unnecessary for this algebra test. Integer lifting is tested separately.
	x, y := f.Bounded(c.X[:], f.ReducedWidths()), f.Bounded(c.Y[:], f.ReducedWidths())
	terms := []term{{big.NewInt(1), []*Element{x, y}}}
	fold := f.arithmetic.fold(8, 14)
	for end := 1; end < 8; end++ {
		native, low := f.pairProjectedForms(terms, 14, fold, end)
		if native == nil {
			return fmt.Errorf("projection end %d did not admit the nine-product kernel", end)
		}
		api.AssertIsEqual(f.build(native), c.Expected[2*(end-1)])
		api.AssertIsEqual(f.build(low), c.Expected[2*(end-1)+1])
	}
	return nil
}

func projectionExpected(x, y []*big.Int, q *big.Int) [14]frontend.Variable {
	p := elliptic.P256().Params().P
	s := &arithmeticState{foldDigits: balancedDigits(new(big.Int).Mod(pow2(256), p), 32, 8)}
	fold := s.fold(8, 14)
	coeffs := make([]*big.Int, 8)
	for k := range coeffs {
		coeffs[k] = new(big.Int)
	}
	for i, a := range x {
		for j, b := range y {
			ab := new(big.Int).Mul(a, b)
			for k := range coeffs {
				coeffs[k].Add(coeffs[k], new(big.Int).Mul(ab, fold[i+j][k]))
			}
		}
	}
	native, low := new(big.Int), new(big.Int)
	for k, c := range coeffs {
		native.Add(native, new(big.Int).Mul(c, pow2(32*k)))
	}
	native.Mod(native, q)
	var out [14]frontend.Variable
	for end := 1; end < 8; end++ {
		low.Add(low, new(big.Int).Mul(coeffs[end-1], pow2(32*(end-1))))
		out[2*(end-1)] = new(big.Int).Set(native)
		out[2*(end-1)+1] = new(big.Int).Mod(new(big.Int).Set(low), q)
	}
	return out
}

func TestProjectionPairMatchesFoldedProduct(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &projectionPairCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if cs.GetNbConstraints() > 7*9+14 {
		t.Fatalf("two-projection products cost %d constraints, expected at most 77", cs.GetNbConstraints())
	}
	solve := func(x, y []*big.Int) {
		t.Helper()
		var assignment projectionPairCircuit
		for i := range x {
			assignment.X[i], assignment.Y[i] = x[i], y[i]
		}
		assignment.Expected = projectionExpected(x, y, q)
		w, err := frontend.NewWitness(&assignment, q)
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			x, y := make([]*big.Int, 8), make([]*big.Int, 8)
			for k := range x {
				x[k], y[k] = new(big.Int), new(big.Int)
			}
			x[i].SetInt64(1)
			y[j].SetInt64(1)
			solve(x, y)
		}
	}
	rng := rand.New(rand.NewSource(20261011))
	for trial := 0; trial < 20; trial++ {
		x, y := make([]*big.Int, 8), make([]*big.Int, 8)
		for k := range x {
			x[k] = new(big.Int).Rand(rng, q)
			y[k] = new(big.Int).Rand(rng, q)
			if k%2 == 0 {
				x[k].Neg(x[k])
			}
			if k%3 == 0 {
				y[k].Neg(y[k])
			}
		}
		solve(x, y)
	}
}

var projectionLayout = Layout{NbLimbs: 8, LimbBits: 32, PieceBits: 11}

func plainLimbs(value *big.Int) [8]frontend.Variable {
	var out [8]frontend.Variable
	for i, limb := range projectionLayout.decompose(value, 8) {
		out[i] = limb
	}
	return out
}
