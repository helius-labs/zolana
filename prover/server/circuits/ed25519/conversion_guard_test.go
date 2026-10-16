package ed25519

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

type edFromMontGuardCircuit struct{}

func (*edFromMontGuardCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := &montPoint{x: c.fp.Const(montOffset), y: c.fp.Const(big.NewInt(0))}
	out := c.edFromMont(p)
	api.AssertIsEqual(out.x.Limbs()[0], 7)
	return nil
}

type montFromEdGuardCircuit struct{}

func (*montFromEdGuardCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := &point{x: c.fp.Const(big.NewInt(0)), y: c.fp.Const(new(big.Int).Sub(fieldPrime(), big.NewInt(1)))}
	out := c.montFromEd(p)
	api.AssertIsEqual(out.y.Limbs()[0], 7)
	return nil
}

func TestConversionGuardsRejectForgedExceptionalHints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		circuit frontend.Circuit
		hint    solver.Hint
		forge   func(*big.Int, []*big.Int, []*big.Int) error
	}{
		{"Montgomery to Edwards", &edFromMontGuardCircuit{}, edFromMontHint, func(q *big.Int, in, out []*big.Int) error {
			if err := edFromMontHint(q, in, out); err != nil {
				return err
			}
			out[0].SetInt64(7)
			return nil
		}},
		{"Edwards to Montgomery", &montFromEdGuardCircuit{}, montFromEdHint, func(q *big.Int, in, out []*big.Int) error {
			return emfield.Unwrap(q, in, out, func(_ *big.Int, _, _, result []*big.Int) error {
				result[0].Set(montOffset)
				result[1].SetInt64(7)
				return nil
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, tc.circuit)
			if err != nil {
				t.Fatal(err)
			}
			w, err := frontend.NewWitness(tc.circuit, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			called := false
			forge := func(q *big.Int, in, out []*big.Int) error {
				called = true
				return tc.forge(q, in, out)
			}
			hintattack.RequireConstraintRejection(t, cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(tc.hint), forge)))
			if !called {
				t.Fatal("conversion hint was not exercised")
			}
		})
	}
}
