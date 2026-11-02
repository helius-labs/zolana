package nonnative

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CRT product reconstruction matches the folded coefficient calculation.
func TestCRTProductMatchesTheFold(t *testing.T) {
	q := ecc.BN254.ScalarField()
	s := newArithmeticState(&Field{layout: edProjectionLayout, mod: edProjectionPrime})
	f := &Field{layout: edProjectionLayout, mod: edProjectionPrime, arithmetic: s}
	b := s.crtBasis(f, q)
	if b == nil || !b.quadratic || len(b.forms) != 9 {
		t.Fatal("X^6-152 must split into three X^2=d factors with nine products")
	}
	rows := s.fold(6, 10)
	bound := pow2(44)
	for trial := 0; trial < 64; trial++ {
		x, y := make([]*big.Int, 6), make([]*big.Int, 6)
		for i := range x {
			x[i], _ = rand.Int(rand.Reader, bound)
			y[i], _ = rand.Int(rand.Reader, bound)
			x[i].Sub(x[i], pow2(43))
			y[i].Sub(y[i], pow2(43))
		}
		want := make([]*big.Int, 6)
		for j := range want {
			want[j] = new(big.Int)
		}
		for i, c := range polyMulAbs(x, y) {
			for j := range want {
				want[j].Add(want[j], new(big.Int).Mul(c, rows[i][j]))
			}
		}
		got := b.foldedProduct(x, y, q)
		for j := range want {
			if new(big.Int).Mod(want[j], q).Cmp(got[j]) != 0 {
				t.Fatalf("trial %d coefficient %d: residue basis disagrees with the fold", trial, j)
			}
		}
	}
}

func (b *crtBasis) foldedProduct(x, y []*big.Int, q *big.Int) []*big.Int {
	w := make([]*big.Int, len(b.forms))
	for k, form := range b.forms {
		l, r := new(big.Int), new(big.Int)
		for i, c := range form {
			if i < len(x) {
				l.Add(l, new(big.Int).Mul(c, x[i]))
			}
			if i < len(y) {
				r.Add(r, new(big.Int).Mul(c, y[i]))
			}
		}
		w[k] = l.Mul(l, r).Mod(l, q)
	}
	out := make([]*big.Int, len(b.combine))
	for j, row := range b.combine {
		out[j] = new(big.Int)
		for k, c := range row {
			out[j].Add(out[j], new(big.Int).Mul(c, w[k]))
		}
		out[j].Mod(out[j], q)
	}
	return out
}

// Construction certifies both tensors, so one wrong coefficient panics.
func TestCRTBasisCertificationRejectsCorruption(t *testing.T) {
	q := ecc.BN254.ScalarField()
	f := polyReduce(poly{big.NewInt(-152), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), big.NewInt(1)}, q)
	interpolation := func(d int) [][]*big.Int {
		return (&arithmeticState{inverseMatrices: map[int][][]*big.Int{}}).inverseVandermonde(d, q)
	}
	powers := residueColumns(11, f, q)
	requirePanic := func(name, want string, run func()) {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != want {
					t.Fatalf("recovered %v, want %q", r, want)
				}
			}()
			run()
		})
	}
	requirePanic("interpolation", "CRT product tensor mismatch", func() {
		newCRTBasis(f, 6, q, func(d int) [][]*big.Int {
			m := interpolation(d)
			m[0][1] = new(big.Int).Add(m[0][1], big.NewInt(1))
			return m
		})
	})
	for _, tc := range []struct {
		name, want string
		corrupt    func(*crtBasis)
		certify    func(*crtBasis)
	}{
		{"combine", "CRT product tensor mismatch", func(b *crtBasis) { b.combine[2][1].Add(b.combine[2][1], big.NewInt(1)) }, func(b *crtBasis) { b.certifyProducts(powers, q) }},
		{"form", "CRT product tensor mismatch", func(b *crtBasis) { b.forms[4][5].Add(b.forms[4][5], big.NewInt(1)) }, func(b *crtBasis) { b.certifyProducts(powers, q) }},
		{"square combine", "CRT square tensor mismatch", func(b *crtBasis) { b.squareCombine[3][0].Add(b.squareCombine[3][0], big.NewInt(1)) }, func(b *crtBasis) { b.certifySquares(powers, q) }},
		{"square form", "CRT square tensor mismatch", func(b *crtBasis) { b.squareRight[1][4].Add(b.squareRight[1][4], big.NewInt(1)) }, func(b *crtBasis) { b.certifySquares(powers, q) }},
	} {
		b := newCRTBasis(f, 6, q, interpolation)
		tc.corrupt(b)
		requirePanic(tc.name, tc.want, func() { tc.certify(b) })
	}
}

// 2^425 folds to 19*2^170, so this layout folds by X^5-19X^2 with a double root at zero.
var repeatedRootLayout = Layout{NbLimbs: 5, LimbBits: 85, PieceBits: 10}

type repeatedRootCircuit struct {
	A, C [5]frontend.Variable
	B    frontend.Variable
}

func (c *repeatedRootCircuit) Define(api frontend.API) error {
	f := NewFor(api, edProjectionPrime, repeatedRootLayout)
	a, product := fromLimbs(f, c.A[:]), fromLimbs(f, c.C[:])
	// Two full-width operands overflow the quotient range, so b gets small proved bounds.
	f.RangeChecker().Check(c.B, 4)
	lo, hi := make([]*big.Int, 5), make([]*big.Int, 5)
	for i := range lo {
		lo[i], hi[i] = new(big.Int), new(big.Int)
	}
	hi[0].SetInt64(15)
	b := f.WithBounds([]frontend.Variable{c.B, 0, 0, 0, 0}, lo, hi)
	f.AssertZero(T(1, a, b), T(-1, product))
	return nil
}

func TestRepeatedRootFoldMultiplies(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &repeatedRootCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := rand.Int(rand.Reader, edProjectionPrime)
	if err != nil {
		t.Fatal(err)
	}
	product := new(big.Int).Mul(a, big.NewInt(13))
	product.Mod(product, edProjectionPrime)
	assign := func(c *big.Int) *repeatedRootCircuit {
		w := &repeatedRootCircuit{B: 13}
		for i, l := range repeatedRootLayout.decompose(a, 5) {
			w.A[i] = l
		}
		for i, l := range repeatedRootLayout.decompose(c, 5) {
			w.C[i] = l
		}
		return w
	}
	honest, err := frontend.NewWitness(assign(product), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(honest); err != nil {
		t.Fatal(err)
	}
	wrong := new(big.Int).Add(product, big.NewInt(1))
	forged, err := frontend.NewWitness(assign(wrong.Mod(wrong, edProjectionPrime)), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(forged) == nil {
		t.Fatal("wrong product accepted")
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, honest)
	if err != nil {
		t.Fatal(err)
	}
	public, err := honest.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
}
