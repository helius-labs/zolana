package emfield

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestLazyBoundExpansionPreservesPolynomial(t *testing.T) {
	rng := rand.New(rand.NewSource(129))
	for trial := 0; trial < 100; trial++ {
		nbLimbs := 6
		if trial%2 == 0 {
			nbLimbs = 8
		}
		leaf := func() *Element {
			e := &Element{limbs: make([]frontend.Variable, nbLimbs), lo: make([]*big.Int, nbLimbs), hi: make([]*big.Int, nbLimbs)}
			for i := range e.limbs {
				e.limbs[i] = big.NewInt(rng.Int63n(101) - 50)
				e.lo[i], e.hi[i] = big.NewInt(-50), big.NewInt(50)
			}
			return e
		}
		lin := func(coefs []int64, elems ...*Element) *Element {
			e := &Element{limbs: make([]frontend.Variable, nbLimbs), lo: make([]*big.Int, nbLimbs), hi: make([]*big.Int, nbLimbs)}
			for i := range e.limbs {
				e.limbs[i] = new(big.Int)
				e.lo[i], e.hi[i] = new(big.Int), new(big.Int)
			}
			for j, a := range elems {
				coef := big.NewInt(coefs[j])
				e.parts = append(e.parts, part{coef: coef, e: a})
				for i := range e.limbs {
					e.limbs[i].(*big.Int).Add(e.limbs[i].(*big.Int), new(big.Int).Mul(coef, a.limbs[i].(*big.Int)))
					lo, hi := intervalMul(a.lo[i], a.hi[i], coef, coef)
					e.lo[i].Add(e.lo[i], lo)
					e.hi[i].Add(e.hi[i], hi)
				}
			}
			return e
		}
		a, b, c := leaf(), leaf(), leaf()
		ab := lin([]int64{1, 1}, a, b)
		nested := lin([]int64{3, -2, -3}, ab, c, a)
		terms := []term{
			{coef: big.NewInt(1), factors: []*Element{ab, ab}},
			{coef: big.NewInt(-1), factors: []*Element{a, a}},
			{coef: big.NewInt(-2), factors: []*Element{b, a}},
			{coef: big.NewInt(7), factors: []*Element{nested, ab}},
			{coef: big.NewInt(-7), factors: []*Element{ab, nested}},
			{coef: big.NewInt(4), factors: []*Element{nested}},
			{coef: big.NewInt(-3)},
		}
		eval := func(ts []term) []*big.Int {
			out := make([]*big.Int, 2*nbLimbs-1)
			for i := range out {
				out[i] = new(big.Int)
			}
			for _, term := range ts {
				p := []*big.Int{new(big.Int).Set(term.coef)}
				for _, e := range term.factors {
					limbs := make([]*big.Int, len(e.limbs))
					for i, l := range e.limbs {
						limbs[i] = l.(*big.Int)
					}
					p = polyMulAbs(p, limbs)
				}
				out = addInto(out, p)
			}
			return out
		}
		want, got := eval(terms), eval(lazyBoundTerms(terms))
		lo, hi := lazyBoundIntervals(terms)
		for i := range want {
			if want[i].Cmp(got[i]) != 0 {
				t.Fatalf("trial %d coefficient %d: expanded polynomial differs", trial, i)
			}
			if want[i].Cmp(lo[i]) < 0 || want[i].Cmp(hi[i]) > 0 {
				t.Fatalf("trial %d coefficient %d: true coefficient outside intersected interval", trial, i)
			}
		}
	}
}

type lazySquareBoundsCircuit struct {
	Lay      Layout `gnark:"-"`
	A, B     [8]frontend.Variable
	Expected [8]frontend.Variable `gnark:",public"`
}

func (c *lazySquareBoundsCircuit) Define(api frontend.API) error {
	f := NewFor(api, p256P, c.Lay)
	a, b := f.FromLimbs(c.A[:]), f.FromLimbs(c.B[:])
	ab := f.Add(a, b)
	r := f.Lazy(T(1, ab, ab), T(-1, a, a))
	f.AssertZero(T(1, r), T(-1, f.FromLimbs(c.Expected[:])))
	for _, zero := range []*Element{
		f.Lazy(T(1, ab), T(-1, a), T(-1, b)),
		f.Lazy(T(1, ab, ab), T(-1, a, a), T(-1, b, b), T(-2, a, b)),
	} {
		for i, l := range zero.limbs {
			if zero.lo[i].Sign() != 0 || zero.hi[i].Sign() != 0 {
				return fmt.Errorf("exactly canceled polynomial has nonzero bounds at limb %d", i)
			}
			api.AssertIsEqual(l, 0)
		}
	}
	return nil
}

func TestLazySquareBoundsAndCancellation(t *testing.T) {
	rng := rand.New(rand.NewSource(256))
	for _, l := range layouts {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lazySquareBoundsCircuit{Lay: l.lay})
		if err != nil {
			t.Fatal(err)
		}
		for trial := 0; trial < 20; trial++ {
			a, b := new(big.Int).Rand(rng, p256P), new(big.Int).Rand(rng, p256P)
			if trial == 0 {
				a.SetInt64(0)
				b.Sub(p256P, big.NewInt(1))
			} else if trial == 1 {
				a.Sub(p256P, big.NewInt(1))
				b.Set(a)
			}
			want := new(big.Int).Mul(b, new(big.Int).Add(new(big.Int).Lsh(a, 1), b))
			want.Mod(want, p256P)
			w := &lazySquareBoundsCircuit{Lay: l.lay, A: plainLimbs(a), B: plainLimbs(b), Expected: plainLimbs(want)}
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err != nil {
				t.Fatalf("%s trial %d: square difference/cancellation failed: %v", l.name, trial, err)
			}
		}
	}
}
