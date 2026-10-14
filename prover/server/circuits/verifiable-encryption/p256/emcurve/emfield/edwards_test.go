package emfield

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type edwardsFieldCircuit struct{ A, B, Expected [6]frontend.Variable }

func (v *edwardsFieldCircuit) Define(api frontend.API) error {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	f := NewFor(api, p, Config{Layout: Layout{NbLimbs: 6, LimbBits: 43, PieceBits: 11}, Arithmetic: ArithmeticV2})
	a, b := f.FromLimbs(v.A[:]), f.FromLimbs(v.B[:])
	f.AssertCanonical(a)
	f.AssertCanonical(b)
	r := f.Eval(T(1, a, b))
	f.AssertCanonical(r)
	for i, l := range r.Limbs() {
		api.AssertIsEqual(l, v.Expected[i])
	}
	return nil
}
func TestEdwardsFoldAndCanonicalEdges(t *testing.T) {
	p := new(big.Int).Sub(pow2(255), big.NewInt(19))
	lay := Layout{NbLimbs: 6, LimbBits: 43, PieceBits: 11}
	s := newArithmeticState(&Field{config: Config{Layout: lay}, mod: p})
	if s.foldDigits == nil || s.foldDigits[0].Cmp(big.NewInt(152)) != 0 {
		t.Fatal("wrong Edwards fold")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &edwardsFieldCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(a, b *big.Int) error {
		w := &edwardsFieldCircuit{}
		for i, l := range lay.decompose(a, 6) {
			w.A[i] = l
		}
		for i, l := range lay.decompose(b, 6) {
			w.B[i] = l
		}
		product := new(big.Int).Mod(new(big.Int).Mul(a, b), p)
		for i, l := range lay.decompose(product, 6) {
			w.Expected[i] = l
		}
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		return cs.IsSolved(wit)
	}
	for _, a := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(pow2(43), big.NewInt(1)), pow2(43), new(big.Int).Add(pow2(43), big.NewInt(1))} {
		if err := solve(a, new(big.Int).Sub(p, big.NewInt(1))); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []*big.Int{p, new(big.Int).Add(p, big.NewInt(1)), new(big.Int).Sub(pow2(255), big.NewInt(1))} {
		if solve(a, big.NewInt(1)) == nil {
			t.Fatal("noncanonical Edwards element accepted")
		}
	}
}
