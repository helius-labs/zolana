package emfield

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type plainScalarTripleCircuit struct {
	Lay                             Layout `gnark:"-"`
	Projected                       bool   `gnark:"-"`
	A, B                            [8]frontend.Variable
	Scalar                          frontend.Variable
	Product, Square                 [8]frontend.Variable `gnark:",public"`
	Linear, ScalarsOnly, TwoScalars [8]frontend.Variable `gnark:",public"`
}

func (c *plainScalarTripleCircuit) Define(api frontend.API) error {
	f := NewFor(api, p256P, c.Lay)
	a, b := f.FromLimbs(c.A[:]), f.FromLimbs(c.B[:])
	f.RangeChecker().Check(c.Scalar, 8)
	s := f.Bounded([]frontend.Variable{c.Scalar}, []int{8})
	eval := f.Eval
	if c.Projected {
		eval = f.EvalProjected
	}
	for _, pair := range []struct {
		right    *Element
		expected [8]frontend.Variable
	}{{b, c.Product}, {a, c.Square}} {
		for _, factors := range [][]*Element{{s, a, pair.right}, {a, s, pair.right}, {a, pair.right, s}} {
			r := eval(T(1, factors...))
			for i, v := range r.limbs {
				api.AssertIsEqual(v, pair.expected[i])
			}
		}
	}
	for _, row := range []struct {
		factors  []*Element
		expected [8]frontend.Variable
	}{{[]*Element{s, a}, c.Linear}, {[]*Element{a, s}, c.Linear}, {[]*Element{s, s}, c.ScalarsOnly}, {[]*Element{s, a, s, b}, c.TwoScalars}} {
		r := eval(T(1, row.factors...))
		for i, v := range r.limbs {
			api.AssertIsEqual(v, row.expected[i])
		}
	}
	return nil
}

func TestPlainScalarTripleMatchesBigInt(t *testing.T) {
	testPlainScalarTriple(t, false)
}

func TestProjectedScalarTripleMatchesBigInt(t *testing.T) {
	testPlainScalarTriple(t, true)
}

func testPlainScalarTriple(t *testing.T, projected bool) {
	rng := rand.New(rand.NewSource(832))
	for _, l := range layouts {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainScalarTripleCircuit{Lay: l.lay, Projected: projected})
		if err != nil {
			t.Fatal(err)
		}
		for trial := 0; trial < 20; trial++ {
			a, b := new(big.Int).Rand(rng, p256P), new(big.Int).Rand(rng, p256P)
			s := big.NewInt(rng.Int63n(256))
			switch trial {
			case 0:
				s.SetInt64(0)
				a.Sub(p256P, big.NewInt(1))
				b.Set(a)
			case 1:
				s.SetInt64(1)
				a.SetInt64(0)
			case 2:
				s.SetInt64(255)
				a.Sub(p256P, big.NewInt(1))
				b.Set(a)
			}
			product := new(big.Int).Mul(s, new(big.Int).Mul(a, b))
			square := new(big.Int).Mul(s, new(big.Int).Mul(a, a))
			product.Mod(product, p256P)
			square.Mod(square, p256P)
			linear := new(big.Int).Mod(new(big.Int).Mul(s, a), p256P)
			scalarsOnly := new(big.Int).Mod(new(big.Int).Mul(s, s), p256P)
			twoScalars := new(big.Int).Mod(new(big.Int).Mul(s, product), p256P)
			w := &plainScalarTripleCircuit{Lay: l.lay, Projected: projected, A: plainLimbs(a), B: plainLimbs(b), Scalar: s, Product: plainLimbs(product), Square: plainLimbs(square), Linear: plainLimbs(linear), ScalarsOnly: plainLimbs(scalarsOnly), TwoScalars: plainLimbs(twoScalars)}
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err != nil {
				t.Fatalf("%s trial %d: scalar triple disagrees with bigint: %v", l.name, trial, err)
			}
		}
	}
}
