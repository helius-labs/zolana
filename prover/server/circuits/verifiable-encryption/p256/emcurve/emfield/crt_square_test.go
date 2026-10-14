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

// Exercise the frontend polynomial multiplication path directly with arbitrary
// native-field inputs. Integer range certificates are tested separately.
type crtSquareCircuit struct {
	A, Expected                []frontend.Variable
	ModPoly                    []*big.Int `gnark:"-"`
	WantShortcut, ForceGeneric bool       `gnark:"-"`
}

func (c *crtSquareCircuit) Define(api frontend.API) error {
	n := len(c.A)
	modulus := new(big.Int).Sub(pow2(n*43-1), big.NewInt(19))
	f := NewFor(api, modulus, Config{Layout: Layout{NbLimbs: n, LimbBits: 43, PieceBits: 11}, Arithmetic: ArithmeticV2})
	f.arithmetic.foldDigits = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		f.arithmetic.foldDigits[i] = new(big.Int).Neg(c.ModPoly[i])
	}
	f.arithmetic.foldRows = nil
	basis := f.arithmetic.crtBasis(f, api.Compiler().Field())
	if basis == nil {
		return fmt.Errorf("test requires a nontrivial CRT basis")
	}
	if (len(basis.squareLeft) < len(basis.forms)) != c.WantShortcut {
		return fmt.Errorf("unexpected square dispatch: shortcut=%v", len(basis.squareLeft) < len(basis.forms))
	}
	if c.ForceGeneric {
		basis.squareLeft, basis.squareRight, basis.squareCombine = basis.forms, basis.forms, basis.combine
	}
	a := &Element{limbs: c.A}
	forms := f.foldedForms([]term{{coef: big.NewInt(1), factors: []*Element{a, a}}}, 2*n-2, f.arithmetic.fold(n, 2*n-2))
	for i := 0; i < n; i++ {
		api.AssertIsEqual(f.build(forms(i)), c.Expected[i])
	}
	return nil
}

// This oracle uses ordinary coefficient convolution and monic long division,
// independently of the CRT factorization, projections, and square shortcut.
func crtSquareOracle(a, modPoly []*big.Int, q *big.Int) []*big.Int {
	n := len(a)
	v := make([]*big.Int, 2*n-1)
	for i := range v {
		v[i] = new(big.Int)
	}
	for i := range a {
		for j := range a {
			v[i+j].Add(v[i+j], new(big.Int).Mul(a[i], a[j])).Mod(v[i+j], q)
		}
	}
	for k := len(v) - 1; k >= n; k-- {
		lead := new(big.Int).Set(v[k])
		for j := 0; j <= n; j++ {
			v[k-n+j].Sub(v[k-n+j], new(big.Int).Mul(lead, modPoly[j])).Mod(v[k-n+j], q)
		}
	}
	return v[:n]
}
func TestCRTSquareFrontendDifferential(t *testing.T) {
	q := ecc.BN254.ScalarField()
	// Centered quadratic squaring also applies when the irreducible factors
	// have nonzero linear coefficients.
	var cs []*big.Int
	for c := int64(2); len(cs) < 2; c++ {
		disc := new(big.Int).Sub(big.NewInt(1), big.NewInt(4*c))
		if big.Jacobi(disc, q) == -1 {
			cs = append(cs, big.NewInt(c))
		}
	}
	nonBin := []*big.Int{new(big.Int).Mul(cs[0], cs[1]), new(big.Int).Sub(cs[1], cs[0]), new(big.Int).Sub(new(big.Int).Add(cs[0], cs[1]), big.NewInt(1)), new(big.Int), big.NewInt(1)}
	exponent := new(big.Int).Div(new(big.Int).Sub(q, big.NewInt(1)), big.NewInt(3))
	nonCube := big.NewInt(2)
	for new(big.Int).Exp(nonCube, exponent, q).Cmp(big.NewInt(1)) == 0 {
		nonCube.Add(nonCube, big.NewInt(1))
	}
	cubic := []*big.Int{new(big.Int).Set(nonCube), new(big.Int).Neg(nonCube), new(big.Int), big.NewInt(-1), big.NewInt(1)}
	cases := []struct {
		name       string
		polynomial []*big.Int
		shortcut   bool
	}{
		{"three_binomial_quadratics", []*big.Int{big.NewInt(-152), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), big.NewInt(1)}, true},
		{"nonbinomial_quadratics", nonBin, true},
		{"linear_and_irreducible_cubic", cubic, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := len(tc.polynomial) - 1
			circuit := &crtSquareCircuit{A: make([]frontend.Variable, n), Expected: make([]frontend.Variable, n), ModPoly: tc.polynomial, WantShortcut: tc.shortcut}
			compiled, e := frontend.Compile(q, r1cs.NewBuilder, circuit)
			if e != nil {
				t.Fatal(e)
			}
			if tc.shortcut {
				generic := *circuit
				generic.ForceGeneric = true
				old, e := frontend.Compile(q, r1cs.NewBuilder, &generic)
				if e != nil {
					t.Fatal(e)
				}
				if compiled.GetNbConstraints() >= old.GetNbConstraints() {
					t.Fatal("square shortcut did not reduce frontend rows")
				}
				t.Logf("shortcut=%d generic=%d constraints", compiled.GetNbConstraints(), old.GetNbConstraints())
			}
			rng := rand.New(rand.NewSource(20261011))
			vectors := make([][]*big.Int, 0, 32)
			for _, k := range []int64{0, 1, -1} {
				a := make([]*big.Int, n)
				for i := range a {
					a[i] = new(big.Int).Mod(big.NewInt(k), q)
				}
				vectors = append(vectors, a)
			}
			for j := 0; j < n; j++ {
				a := make([]*big.Int, n)
				for i := range a {
					a[i] = new(big.Int)
				}
				a[j].SetInt64(1)
				vectors = append(vectors, a)
			}
			for k := 0; k < 20; k++ {
				a := make([]*big.Int, n)
				for i := range a {
					a[i] = new(big.Int).Rand(rng, q)
				}
				vectors = append(vectors, a)
			}
			for k, a := range vectors {
				expected := crtSquareOracle(a, tc.polynomial, q)
				w := &crtSquareCircuit{A: make([]frontend.Variable, n), Expected: make([]frontend.Variable, n)}
				for i := range a {
					w.A[i] = a[i]
					w.Expected[i] = expected[i]
				}
				wit, e := frontend.NewWitness(w, q)
				if e != nil {
					t.Fatal(e)
				}
				if e = compiled.IsSolved(wit); e != nil {
					t.Fatalf("vector%d: %v", k, e)
				}
				if k == len(vectors)-1 {
					w.Expected[0] = new(big.Int).Add(expected[0], big.NewInt(1))
					bad, e := frontend.NewWitness(w, q)
					if e != nil {
						t.Fatal(e)
					}
					if compiled.IsSolved(bad) == nil {
						t.Fatal("wrong product coefficient accepted")
					}
				}
			}
		})
	}
}

func TestCRTQuadraticSquaresMatchFold(t *testing.T) {
	q := ecc.BN254.ScalarField()
	s := newArithmeticState(&Field{config: Config{Layout: P256Layout}, mod: p256P})
	f := &Field{config: Config{Layout: P256Layout}, mod: p256P, arithmetic: s}
	b := s.crtBasis(f, q)
	if len(b.squareLeft) != 10 || len(b.squareRight) != 10 {
		t.Fatalf("square products %d/%d, want 10", len(b.squareLeft), len(b.squareRight))
	}
	rng := rand.New(rand.NewSource(256))
	for trial := 0; trial < 100; trial++ {
		x := make([]*big.Int, 8)
		for i := range x {
			x[i] = new(big.Int).Rand(rng, q)
			if trial < 8 {
				x[i].SetInt64(0)
				if trial == i {
					x[i].SetInt64(1)
				}
			}
			if trial == 8 {
				x[i].SetInt64(-1)
			}
		}
		products := make([]*big.Int, 10)
		for k := range products {
			left, right := new(big.Int), new(big.Int)
			for i := range x {
				left.Add(left, new(big.Int).Mul(x[i], b.squareLeft[k][i]))
				right.Add(right, new(big.Int).Mul(x[i], b.squareRight[k][i]))
			}
			products[k] = left.Mul(left, right).Mod(left, q)
		}
		want := b.foldedProduct(x, x, q)
		for j, row := range b.squareCombine {
			got := new(big.Int)
			for k, c := range row {
				got.Add(got, new(big.Int).Mul(c, products[k]))
			}
			got.Mod(got, q)
			if got.Cmp(want[j]) != 0 {
				t.Fatalf("trial %d coefficient %d: quadratic square differs from exact fold", trial, j)
			}
		}
	}
}
