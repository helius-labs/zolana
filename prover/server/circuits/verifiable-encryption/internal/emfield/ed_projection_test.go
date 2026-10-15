package emfield

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var edProjectionPrime = new(big.Int).Sub(pow2(255), big.NewInt(19))
var edProjectionLayout = Layout{NbLimbs: 6, LimbBits: 43, PieceBits: 11, Lookups: true}

type edProjectionCircuit struct {
	X, Y                       [6]frontend.Variable
	Expected                   [2]frontend.Variable
	FullExpected               [6]frontend.Variable
	End                        int  `gnark:"-"`
	Square, Precached, Promote bool `gnark:"-"`
}

func (c *edProjectionCircuit) Define(api frontend.API) error {
	f := NewFor(api, edProjectionPrime, edProjectionLayout)
	// This test intentionally covers all native-field vectors. No integer
	// range assumption is used to prove these exact bilinear identities.
	x, y := &Element{limbs: c.X[:]}, &Element{limbs: c.Y[:]}
	if c.Square {
		y = x
	}
	terms := []term{{coef: big.NewInt(1), factors: []*Element{x, y}}}
	fold := f.plain.fold(6, 10)
	if c.Precached {
		f.foldedForms(terms, 10, fold)
	}
	native, low := f.pairProjectedForms(terms, 10, fold, c.End)
	if c.End%2 == 0 && native == nil {
		return fmt.Errorf("expected optimized projection at prefix %d", c.End)
	}
	if native == nil {
		native, low = newLinForm(), newLinForm()
		forms := f.foldedForms(terms, 10, fold)
		for j := 0; j < 6; j++ {
			mergeForm(native, forms(j), pow2(43*j))
			if j < c.End {
				mergeForm(low, forms(j), pow2(43*j))
			}
		}
	}
	api.AssertIsEqual(native.build(api), c.Expected[0])
	api.AssertIsEqual(low.build(api), c.Expected[1])
	if c.Promote {
		forms := f.foldedForms(terms, 10, fold)
		for j := 0; j < 6; j++ {
			api.AssertIsEqual(forms(j).build(api), c.FullExpected[j])
		}
	}
	return nil
}

// Independent ordinary convolution followed by X^6=152. It does not use any
// matrix-pencil, factorization, or CRT reconstruction coefficients.
func edProjectionCoefficients(x, y []*big.Int, q *big.Int) []*big.Int {
	coeff := make([]*big.Int, 6)
	for i := range coeff {
		coeff[i] = new(big.Int)
	}
	for i, a := range x {
		for j, b := range y {
			v := new(big.Int).Mul(a, b)
			k := i + j
			if k >= 6 {
				k -= 6
				v.Mul(v, big.NewInt(152))
			}
			coeff[k].Add(coeff[k], v)
		}
	}
	for _, v := range coeff {
		v.Mod(v, q)
	}
	return coeff
}

func edProjectionOracle(x, y []*big.Int, end int, q *big.Int) [2]frontend.Variable {
	coeff := edProjectionCoefficients(x, y, q)
	all, low := new(big.Int), new(big.Int)
	for j, v := range coeff {
		term := new(big.Int).Mul(v, pow2(43*j))
		all.Add(all, term)
		if j < end {
			low.Add(low, term)
		}
	}
	return [2]frontend.Variable{all.Mod(all, q), low.Mod(low, q)}
}
func TestEdProjectionTensorDifferential(t *testing.T) {
	q := ecc.BN254.ScalarField()
	for _, mode := range []string{"fresh", "square", "cached", "promote"} {
		for end := 1; end < 6; end++ {
			t.Run(fmt.Sprintf("%s/prefix%d", mode, end), func(t *testing.T) {
				circuit := &edProjectionCircuit{End: end, Square: mode == "square", Precached: mode == "cached", Promote: mode == "promote"}
				cs, err := frontend.Compile(q, r1cs.NewBuilder, circuit)
				if err != nil {
					t.Fatal(err)
				}
				rank := 9
				if end%2 == 0 {
					rank = 6
				}
				if end == 3 || circuit.Precached || circuit.Promote {
					rank = 9
				}
				if circuit.Square {
					rank = 6
				}
				equalities := 2
				if circuit.Promote {
					equalities += 6
				}
				if cs.GetNbConstraints() > rank+equalities {
					t.Fatalf("cost %d exceeds %d products plus %d equalities", cs.GetNbConstraints(), rank, equalities)
				}
				t.Logf("%d constraints", cs.GetNbConstraints())
				solve := func(x, y []*big.Int) {
					t.Helper()
					w := &edProjectionCircuit{}
					for i := range x {
						w.X[i] = x[i]
						w.Y[i] = y[i]
					}
					if circuit.Square {
						y = x
					}
					w.Expected = edProjectionOracle(x, y, end, q)
					coeff := edProjectionCoefficients(x, y, q)
					for i := range coeff {
						w.FullExpected[i] = coeff[i].Mod(coeff[i], q)
					}
					witness, err := frontend.NewWitness(w, q)
					if err != nil {
						t.Fatal(err)
					}
					if err := cs.IsSolved(witness); err != nil {
						t.Fatal(err)
					}
					w.Expected[1] = new(big.Int).Add(w.Expected[1].(*big.Int), big.NewInt(1))
					witness, err = frontend.NewWitness(w, q)
					if err != nil {
						t.Fatal(err)
					}
					if cs.IsSolved(witness) == nil {
						t.Fatal("wrong low projection accepted")
					}
				}
				for i := 0; i < 6; i++ {
					for j := 0; j < 6; j++ {
						x, y := make([]*big.Int, 6), make([]*big.Int, 6)
						for k := range x {
							x[k], y[k] = new(big.Int), new(big.Int)
						}
						x[i].SetInt64(1)
						y[j].SetInt64(1)
						solve(x, y)
					}
				}
				rng := rand.New(rand.NewSource(20261011))
				for trial := 0; trial < 24; trial++ {
					x, y := make([]*big.Int, 6), make([]*big.Int, 6)
					for i := range x {
						x[i] = new(big.Int).Rand(rng, q)
						y[i] = new(big.Int).Rand(rng, q)
						if trial == 0 {
							x[i].SetInt64(-1)
						}
						if trial == 1 {
							y[i].SetInt64(0)
						}
					}
					solve(x, y)
				}
			})
		}
	}
}

type edProjectedReducerCircuit struct {
	X, Y                [6]frontend.Variable
	Negative, NoLookups bool `gnark:"-"`
}

func (c *edProjectedReducerCircuit) Define(api frontend.API) error {
	lay := edProjectionLayout
	lay.Lookups = !c.NoLookups
	f := NewFor(api, edProjectionPrime, lay)
	x, y := f.FromLimbs(c.X[:]), f.FromLimbs(c.Y[:])
	if c.Negative {
		x = f.Neg(x)
	}
	// No expected-output equality or canonicality constraint: the reduction
	// certificate itself must reject every wrong field result below 2^255.
	f.EvalProjected(T(1, x, y))
	return nil
}
func TestEdProjectedReducerRejectsAliases(t *testing.T) {
	q := ecc.BN254.ScalarField()
	badR, _ := new(big.Int).SetString("56669709202853789420365878754430393783418211649364570696445368340620554536988", 10)
	// This independent adversarial remainder has zero low-prefix carry in Fq
	// but an enormous native quotient. Removing only the quotient bound must
	// make this forged witness solve; canonicality alone cannot reject it.
	if badR.Sign() < 0 || badR.Cmp(edProjectionPrime) >= 0 || new(big.Int).Mod(new(big.Int).Sub(badR, big.NewInt(2)), edProjectionPrime).Sign() == 0 {
		t.Fatal("invalid malicious remainder fixture")
	}
	base := pow2(86)
	mask := new(big.Int).Sub(base, big.NewInt(1))
	k := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(big.NewInt(2), badR), new(big.Int).ModInverse(edProjectionPrime, q)), q)
	low := new(big.Int).Sub(big.NewInt(2), new(big.Int).And(badR, mask))
	low.Sub(low, new(big.Int).Mul(k, new(big.Int).And(edProjectionPrime, mask)))
	if low.Mod(low, q).Sign() != 0 || k.BitLen() < 200 {
		t.Fatal("fixture must isolate an unbounded quotient with zero low carry")
	}
	// A second independent alias isolates the same bound when the modulus
	// carry digits are balanced: p = 2^169*B-19, q = K*2^169+rem.
	// badR = 2+19*K+rem*B gives a tiny balanced low carry but an 85-bit K.
	balancedK, rem := new(big.Int), new(big.Int)
	balancedK.QuoRem(q, pow2(169), rem)
	balancedBadR := new(big.Int).Add(big.NewInt(2), new(big.Int).Mul(big.NewInt(19), balancedK))
	balancedBadR.Add(balancedBadR, new(big.Int).Mul(rem, base))
	if balancedBadR.Cmp(edProjectionPrime) >= 0 || balancedK.BitLen() < 80 {
		t.Fatal("invalid balanced quotient fixture")
	}
	balancedLow := new(big.Int).Sub(big.NewInt(2), new(big.Int).And(balancedBadR, mask))
	balancedLow.Add(balancedLow, new(big.Int).Mul(big.NewInt(19), balancedK))
	balancedCarry := new(big.Int).Div(balancedLow, base)
	if balancedCarry.Sign() < 0 || balancedCarry.Cmp(big.NewInt(16)) >= 0 || new(big.Int).Mod(balancedLow, base).Sign() != 0 {
		t.Fatal("balanced alias carry is not tiny")
	}
	for _, negative := range []bool{false, true} {
		for _, noLookups := range []bool{false, true} {
			t.Run(fmt.Sprintf("negative%v/plain%v", negative, noLookups), func(t *testing.T) {
				circuit := &edProjectedReducerCircuit{Negative: negative, NoLookups: noLookups}
				cs, err := frontend.Compile(q, r1cs.NewBuilder, circuit)
				if err != nil {
					t.Fatal(err)
				}
				y := big.NewInt(2)
				if negative {
					y = new(big.Int).Sub(edProjectionPrime, big.NewInt(2))
				}
				w := &edProjectedReducerCircuit{}
				for i, v := range edProjectionLayout.decompose(big.NewInt(1), 6) {
					w.X[i] = v
				}
				for i, v := range edProjectionLayout.decompose(y, 6) {
					w.Y[i] = v
				}
				witness, err := frontend.NewWitness(w, q)
				if err != nil {
					t.Fatal(err)
				}
				if err := cs.IsSolved(witness); err != nil {
					t.Fatal(err)
				}
				for _, r := range []*big.Int{big.NewInt(3), new(big.Int).Add(q, big.NewInt(2)), badR, balancedBadR} {
					called := false
					bad := func(q *big.Int, in, out []*big.Int) error {
						called = true
						if err := PlainCheckHint(q, in, out); err != nil {
							return err
						}
						lay, err := layoutOf(in)
						if err != nil {
							return err
						}
						lay.writePieces(out, r, lay.reducedWidths(255))
						return nil
					}
					if cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(PlainCheckHint), bad)) == nil || !called {
						t.Fatalf("forged remainder %s accepted or hint not reached", r)
					}
				}
			})
		}
	}
}
