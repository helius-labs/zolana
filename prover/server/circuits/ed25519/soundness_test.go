package ed25519

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/lookup"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
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
		// A downstream witness generator may refuse a forged intermediate.
		// Totalize its response so only a circuit equation can stop the attack.
		if len(opts) != 0 {
			var total []solver.Option
			for _, hint := range solver.GetRegisteredHints() {
				honest := hint
				total = append(total, solver.OverrideHint(solver.GetHintID(honest), func(q *big.Int, in, out []*big.Int) error {
					if err := honest(q, in, out); err != nil {
						for _, v := range out {
							v.SetInt64(0)
						}
					}
					return nil
				}))
			}
			opts = append(total, opts...)
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
			n := groupOrder()
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
			n.Add(n, groupOrder())
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
	hints := []solver.Hint{decompressHint, byteLimbsHint, lowSplitHint, torsionIndexHint, torsionRootHint, shortScalarsHint, shortRecodeHint, oddRecodeHint, montFromEdHint, edFromMontHint, montTangentHint, montSlopeHint, montSecondHint, distinctHint, emfield.PlainCheckHint, emfield.BalanceHint, lookup.RowLookupHint, lookup.RowCountHint}
	t.Run("offset range", func(t *testing.T) {
		called := false
		bad := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(256); return nil }
		hintattack.RequireConstraintRejection(t, solve(original, solver.OverrideHint(solver.GetHintID(offsetHint), bad)))
		if !called {
			t.Fatal("offset hint was not exercised")
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
		hintattack.RequireConstraintRejection(t, solve(&w, solver.OverrideHint(solver.GetHintID(offsetHint), bad)))
		if !called {
			t.Fatal("offset hint was not exercised")
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
			hintattack.RequireConstraintRejection(t, solve(original, solver.OverrideHint(solver.GetHintID(h), bad)))
			if !called {
				t.Fatal("hint was not exercised")
			}
		})
	}
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
