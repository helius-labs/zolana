package nonnative

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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
