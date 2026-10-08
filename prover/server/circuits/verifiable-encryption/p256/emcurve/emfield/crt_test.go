// Tested invariants and diagnostics:
//
//  1. CRT product reconstruction matches the folded coefficient calculation.
package emfield

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

// Invariant 1: CRT product reconstruction matches the folded coefficient calculation.
func TestPlainCRTProductMatchesTheFold(t *testing.T) {
	q := ecc.BN254.ScalarField()
	s := newArithmeticState(&Field{layout: PlainLayout, mod: p256P})
	f := &Field{layout: PlainLayout, mod: p256P, arithmetic: s}
	b := s.crtBasis(f, q)
	if b == nil {
		t.Fatal("the P-256 fold polynomial has no cheaper residue basis")
	}
	if len(b.forms) != 13 {
		t.Fatalf("%d bilinear products, expected 13 for factor degrees 2, 2 and 4", len(b.forms))
	}
	fp := polyReduce(poly{big.NewInt(-1), new(big.Int), new(big.Int), big.NewInt(1), new(big.Int), new(big.Int), big.NewInt(1), big.NewInt(-1), big.NewInt(1)}, q)
	if new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(pow2(256), pow2(192)), pow2(96)), new(big.Int).Add(pow2(224), big.NewInt(1))).Cmp(p256P) != 0 {
		t.Fatal("the fold polynomial does not evaluate to p at 2^32")
	}
	product := poly{big.NewInt(1)}
	degrees := map[int]int{}
	for _, g := range factorSquarefree(fp, q) {
		product = polyMul(product, g, q)
		degrees[polyDeg(g)]++
	}
	if len(polySub(product, fp, q)) != 0 {
		t.Fatal("the factors do not multiply back to the fold polynomial")
	}
	if degrees[2] != 2 || degrees[4] != 1 || len(degrees) != 2 {
		t.Fatalf("factor degrees %v, expected two quadratics and a quartic", degrees)
	}
	rows := s.fold(8, 14)
	bound := pow2(33)
	for trial := 0; trial < 64; trial++ {
		x, y := make([]*big.Int, 8), make([]*big.Int, 8)
		for i := range x {
			x[i], _ = rand.Int(rand.Reader, bound)
			y[i], _ = rand.Int(rand.Reader, bound)
			x[i].Sub(x[i], pow2(32))
			y[i].Sub(y[i], pow2(32))
		}
		want := make([]*big.Int, 8)
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
