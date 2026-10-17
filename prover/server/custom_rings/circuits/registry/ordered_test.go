package registry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

type orderedCircuit struct{ Enabled, Lo, Mid, Hi frontend.Variable }

func (c *orderedCircuit) Define(api frontend.API) error {
	assertOrderedWhen(api, c.Enabled, c.Lo, c.Mid, c.Hi)
	return nil
}

func TestOrderedBoundariesAndForgedHints(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &orderedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(w *orderedCircuit, options ...solver.Option) error {
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, options...)
	}
	b := new(big.Int).Lsh(big.NewInt(1), 128)
	max := new(big.Int).Sub(q, big.NewInt(1))
	for _, w := range []*orderedCircuit{
		{1, 0, 1, 2}, {1, 0, 1, max},
		{1, new(big.Int).Sub(b, big.NewInt(1)), b, new(big.Int).Add(b, big.NewInt(1))},
		{1, new(big.Int).Sub(max, big.NewInt(2)), new(big.Int).Sub(max, big.NewInt(1)), max},
		{0, max, 0, 0},
	} {
		if err := solve(w); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range []*orderedCircuit{{1, 1, 1, 2}, {1, 0, 2, 2}, {1, max, 0, 1}, {1, 0, max, 1}, {2, 0, 1, 2}} {
		if err := solve(w); err == nil {
			t.Fatal("unordered values accepted")
		}
	}
	for _, attack := range []string{"limb carry", "gap alias", "carry overflow"} {
		t.Run(attack, func(t *testing.T) {
			called := false
			forge := func(field *big.Int, in, out []*big.Int) error {
				called = true
				if err := orderedGapsHint(field, in, out); err != nil {
					return err
				}
				switch attack {
				case "limb carry":
					out[0].Add(out[0], b)
					out[1].Sub(out[1], big.NewInt(1))
				case "gap alias":
					alias := new(big.Int).Add(q, big.NewInt(1))
					out[2].And(alias, new(big.Int).Sub(b, big.NewInt(1)))
					out[3].Rsh(alias, 128)
				case "carry overflow":
					out[8].Add(out[8], big.NewInt(4))
				}
				return nil
			}
			err := solve(&orderedCircuit{1, 0, 2, 4}, solver.OverrideHint(solver.GetHintID(orderedGapsHint), forge), hintattack.SkipMissingLookupQueries(t))
			if !called {
				t.Fatal("forgery did not run")
			}
			hintattack.RequireConstraintRejection(t, err)
		})
	}
}
