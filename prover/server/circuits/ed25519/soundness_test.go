package ed25519

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/ed25519/internal/lookup"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func TestRejectsBadSignaturesAndHints(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &verifyCircuit{Message: make([]frontend.Variable, 32)})
	if err != nil {
		t.Fatal(err)
	}
	original := witnessFor(make([]byte, 32))
	solve := func(w *verifyCircuit, opts ...solver.Option) error {
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		return cs.IsSolved(wit, opts...)
	}
	if err := solve(original); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*verifyCircuit){
		"message":        func(w *verifyCircuit) { w.Message[0] = 1 },
		"signature R":    func(w *verifyCircuit) { w.Signature[0] = w.Signature[0].(byte) ^ 1 },
		"signature S":    func(w *verifyCircuit) { w.Signature[32] = w.Signature[32].(byte) ^ 1 },
		"key":            func(w *verifyCircuit) { w.PublicKey[0] = w.PublicKey[0].(byte) ^ 1 },
		"message byte":   func(w *verifyCircuit) { w.Message[0] = 256 },
		"key byte":       func(w *verifyCircuit) { w.PublicKey[0] = 256 },
		"signature byte": func(w *verifyCircuit) { w.Signature[32] = 256 },
		"S equal L": func(w *verifyCircuit) {
			n := Order()
			for i := 32; i < 64; i++ {
				w.Signature[i] = byte(n.Uint64())
				n.Rsh(n, 8)
			}
		},
		"S plus L": func(w *verifyCircuit) {
			n := new(big.Int)
			for i := 63; i >= 32; i-- {
				n.Lsh(n, 8).Add(n, new(big.Int).SetUint64(uint64(w.Signature[i].(byte))))
			}
			n.Add(n, Order())
			for i := 32; i < 64; i++ {
				w.Signature[i] = byte(n.Uint64())
				n.Rsh(n, 8)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := *original
			w.Message = append([]frontend.Variable{}, original.Message...)
			change(&w)
			if solve(&w) == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
	hints := []solver.Hint{decompressHint, byteLimbsHint, lowSplitHint, torsionIndexHint, torsionRootHint, torsionQuotientHint, shortScalarsHint, shortRecodeHint, oddRecodeHint, montFromEdHint, edFromMontHint, montTangentHint, montSlopeHint, montSecondHint, distinctHint, emfield.PlainCheckHint, emfield.BalanceHint, lookup.RowLookupHint, lookup.RowCountHint}
	t.Run("offset range", func(t *testing.T) {
		called := false
		bad := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(256); return nil }
		if solve(original, solver.OverrideHint(solver.GetHintID(offsetHint), bad)) == nil || !called {
			t.Fatal("out-of-range offset accepted")
		}
	})
	// Offset choices are deliberately nonunique: changing j cannot authorize
	// an invalid signature because both fixed-base corrections use the same j.
	t.Run("alternative offset cannot forge", func(t *testing.T) {
		w := *original
		w.Message = append([]frontend.Variable{}, original.Message...)
		w.Signature[32] = w.Signature[32].(byte) ^ 1
		called := false
		bad := func(q *big.Int, in, out []*big.Int) error {
			called = true
			if err := offsetHint(q, in, out); err != nil {
				return err
			}
			out[0].Add(out[0], big.NewInt(1))
			return nil
		}
		if solve(&w, solver.OverrideHint(solver.GetHintID(offsetHint), bad)) == nil || !called {
			t.Fatal("alternative offset forged a signature")
		}
	})
	for _, fn := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(fn), "sha512.sha512ChunksHint") {
			hints = append(hints, fn)
		}
	}
	for _, h := range hints {
		t.Run(solver.GetHintName(h), func(t *testing.T) {
			called := false
			bad := func(q *big.Int, in, out []*big.Int) error {
				called = true
				if err := h(q, in, out); err != nil {
					return err
				}
				out[0].Add(out[0], big.NewInt(1))
				return nil
			}
			if solve(original, solver.OverrideHint(solver.GetHintID(h), bad)) == nil {
				t.Fatal("forged hint accepted")
			}
			if !called {
				t.Fatal("hint was not exercised")
			}
		})
	}
}

type aliasCircuit struct{ M, L []frontend.Variable }

func (v *aliasCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	widths := c.fp.ReducedWidths()
	lo, hi := make([]*big.Int, len(widths)), make([]*big.Int, len(widths))
	for i, w := range widths {
		lo[i] = new(big.Int).Neg(pow2(w - 1))
		hi[i] = new(big.Int).Sub(pow2(w-1), big.NewInt(1))
		c.fp.RangeChecker().Check(api.Add(v.M[i], pow2(w-1)), w)
		c.fp.RangeChecker().Check(api.Add(v.L[i], pow2(w-1)), w)
	}
	c.assertSlopeSumNonzero(c.fp.WithBounds(v.M, lo, hi), c.fp.WithBounds(v.L, lo, hi))
	return nil
}
func TestSlopeGuardNativeAliases(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &aliasCircuit{M: make([]frontend.Variable, layout.NbLimbs), L: make([]frontend.Variable, layout.NbLimbs)})
	if err != nil {
		t.Fatal(err)
	}
	widths := newCurveWidths()
	off := new(big.Int)
	for i, w := range widths {
		off.Add(off, new(big.Int).Lsh(pow2(w-1), uint(i*layout.LimbBits)))
	}
	max := new(big.Int).Sub(new(big.Int).Sub(pow2(255), off), big.NewInt(1))
	min := new(big.Int).Neg(off)
	pack := func(v *big.Int) []frontend.Variable {
		raw := new(big.Int).Add(v, off)
		out := make([]frontend.Variable, len(widths))
		for i, w := range widths {
			out[i] = new(big.Int).Sub(new(big.Int).And(new(big.Int).Rsh(raw, uint(i*layout.LimbBits)), new(big.Int).Sub(pow2(w), big.NewInt(1))), pow2(w-1))
		}
		return out
	}
	count := 0
	for k := -1; k <= 1; k++ {
		for n := -8; n <= 8; n++ {
			for _, eps := range []int64{-1, 0, 1} {
				sum := new(big.Int).Mul(big.NewInt(int64(k)), Prime())
				sum.Add(sum, new(big.Int).Mul(big.NewInt(int64(n)), ecc.BN254.ScalarField())).Add(sum, big.NewInt(eps))
				l := new(big.Int).Div(sum, big.NewInt(3))
				m := new(big.Int).Sub(sum, new(big.Int).Lsh(new(big.Int).Set(l), 1))
				if l.Cmp(min) < 0 || l.Cmp(max) > 0 || m.Cmp(min) < 0 || m.Cmp(max) > 0 {
					continue
				}
				wit, err := frontend.NewWitness(&aliasCircuit{M: pack(m), L: pack(l)}, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				err = cs.IsSolved(wit)
				want := new(big.Int).Mod(sum, Prime()).Sign() != 0
				if (err == nil) != want {
					t.Fatalf("k%d n%d eps%d accept%v error%v", k, n, eps, want, err)
				}
				if k == 0 && n == 1 && eps == 0 {
					called := false
					bad := func(q *big.Int, in, out []*big.Int) error {
						called = true
						if err := slopeAliasHint(q, in, out); err != nil {
							return err
						}
						out[0].Add(out[0], big.NewInt(1))
						return nil
					}
					if cs.IsSolved(wit, solver.OverrideHint(solver.GetHintID(slopeAliasHint), bad)) == nil || !called {
						t.Fatal("false alias correction accepted")
					}
				}
				count++
			}
		}
	}
	t.Logf("%d exact native-alias boundary cases", count)
}
func newCurveWidths() []int {
	out := make([]int, layout.NbLimbs)
	for i := range out {
		out[i] = min(layout.LimbBits, 255-layout.LimbBits*i)
	}
	return out
}

// With D=T, the first chord equation alone leaves its slope free. The final
// curve assertion and nonzero product guards determine the true tangent.
type coincidentQuadCircuit struct{}

func (*coincidentQuadCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := hostMont(hostMul(generator(), big.NewInt(4)))
	q := hostMont(hostMul(generator(), big.NewInt(8)))
	r := c.quadrupleAddChecked(&montPoint{c.fp.Const(p.x), c.fp.Const(p.y)}, &montPoint{c.fp.Const(q.x), c.fp.Const(q.y)})
	c.assertMontOnCurve(c.montReduce(r))
	return nil
}
func TestFinalCurveRejectsFreeCoincidentChord(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coincidentQuadCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	wit, err := frontend.NewWitness(&coincidentQuadCircuit{}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(wit); err != nil {
		t.Fatal(err)
	}
	called := false
	bad := func(q *big.Int, in, out []*big.Int) error {
		called = true
		for _, v := range out {
			v.SetInt64(0)
		}
		return nil
	}
	if cs.IsSolved(wit, solver.OverrideHint(solver.GetHintID(montSlopeHint), bad)) == nil || !called {
		t.Fatal("free coincident chord slope accepted")
	}
}

func TestRejectsZeroReconstruction(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &verifyCircuit{Message: make([]frontend.Variable, 32)})
	if err != nil {
		t.Fatal(err)
	}
	w := witnessFor(make([]byte, 32))
	w.Message[0] = 1
	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	called := false
	zero := func(_ *big.Int, _, out []*big.Int) error {
		called = true
		for _, v := range out {
			v.SetInt64(0)
		}
		return nil
	}
	if cs.IsSolved(wit, solver.OverrideHint(solver.GetHintID(shortScalarsHint), zero)) == nil || !called {
		t.Fatal("zero reconstruction forged an invalid signature")
	}
}
