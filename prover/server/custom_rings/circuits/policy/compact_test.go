package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

type amountCompareCircuit struct{ Total, Threshold, Result frontend.Variable }

func (c *amountCompareCircuit) Define(api frontend.API) error {
	p := CustomRingPolicyCircuit{FixedInputs: 2}
	api.AssertIsEqual(p.amountAtMost(api, c.Total, c.Threshold), c.Result)
	return nil
}

func TestCompactAmountComparison(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &amountCompareCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(w *amountCompareCircuit, options ...solver.Option) error {
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, options...)
	}
	max := new(big.Int).Sub(amountSumOffset, big.NewInt(1))
	for _, tc := range []amountCompareCircuit{{0, 0, 1}, {1, 0, 0}, {0, 1, 1}, {max, max, 1}, {max, 0, 0}, {0, max, 1}, {100, 99, 0}, {99, 100, 1}} {
		if err := solve(&tc); err != nil {
			t.Fatal(err)
		}
		tc.Result = 1 - tc.Result.(int)
		if err := solve(&tc); err == nil {
			t.Fatal("wrong comparison accepted")
		}
	}
	for _, name := range []string{"borrow", "high bit"} {
		t.Run(name, func(t *testing.T) {
			called := false
			forge := func(field *big.Int, in, out []*big.Int) error {
				called = true
				if err := amountComparisonHint(field, in, out); err != nil {
					return err
				}
				out[0].Sub(out[0], amountSumOffset)
				out[1].Add(out[1], big.NewInt(1))
				return nil
			}
			w := &amountCompareCircuit{1, 0, 1}
			if name == "high bit" {
				w = &amountCompareCircuit{0, 1, 2}
			}
			err := solve(w, solver.OverrideHint(solver.GetHintID(amountComparisonHint), forge), hintattack.SkipMissingLookupQueries(t))
			if !called {
				t.Fatal("forgery did not run")
			}
			hintattack.RequireConstraintRejection(t, err)
		})
	}
}

type decodeRuleCircuit struct{ Packed frontend.Variable }

func (c *decodeRuleCircuit) Define(api frontend.API) error {
	a, b := decodeRule(api, c.Packed), decodeRuleCompact(api, c.Packed)
	for i, x := range []frontend.Variable{a.mode, a.threshold, a.altMask, a.onOwner, a.onAsset, a.onSender, a.present, a.absent, a.inline, a.hasAlternative, a.always, a.scalarGuard, a.assetGuard} {
		api.AssertIsEqual(x, []frontend.Variable{b.mode, b.threshold, b.altMask, b.onOwner, b.onAsset, b.onSender, b.present, b.absent, b.inline, b.hasAlternative, b.always, b.scalarGuard, b.assetGuard}[i])
	}
	for i := range a.listBits {
		api.AssertIsEqual(a.listBits[i], b.listBits[i])
		api.AssertIsEqual(a.altBits[i], b.altBits[i])
	}
	return nil
}

func TestCompactRuleDecode(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &decodeRuleCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(n *big.Int, options ...solver.Option) error {
		w, err := frontend.NewWitness(&decodeRuleCircuit{n}, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(w, options...)
	}
	for i := uint(0); i < 104; i++ {
		if err := solve(new(big.Int).Lsh(big.NewInt(1), i)); err != nil {
			t.Fatal(err)
		}
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 104), big.NewInt(1))
	if err := solve(max); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		called := false
		forge := func(field *big.Int, in, out []*big.Int) error {
			called = true
			if err := rulePartsHint(field, in, out); err != nil {
				return err
			}
			shift := uint(8)
			if i == 4 {
				shift = 64
			}
			out[i].Add(out[i], new(big.Int).Lsh(big.NewInt(1), shift))
			out[i+1].Sub(out[i+1], big.NewInt(1))
			return nil
		}
		err := solve(max, solver.OverrideHint(solver.GetHintID(rulePartsHint), forge), hintattack.SkipMissingLookupQueries(t))
		if !called {
			t.Fatal("forgery did not run")
		}
		hintattack.RequireConstraintRejection(t, err)
	}
}

type shapedAmountCompareCircuit struct {
	Total, Threshold, Result frontend.Variable
	Inputs                   int `gnark:"-"`
}

func (c *shapedAmountCompareCircuit) Define(api frontend.API) error {
	p := CustomRingPolicyCircuit{Dynamic: &ShapeWires{Inputs: make([]UtxoWires, c.Inputs), Outputs: make([]OutputWires, 4)}}
	api.AssertIsEqual(p.amountAtMost(api, c.Total, c.Threshold), c.Result)
	return nil
}

func TestShapedAmountComparisonLargestAggregate(t *testing.T) {
	const inputs = 16
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &shapedAmountCompareCircuit{Inputs: inputs})
	if err != nil {
		t.Fatal(err)
	}
	offset := new(big.Int).Lsh(big.NewInt(1), 68)
	max := new(big.Int).Sub(offset, big.NewInt(1))
	solve := func(w *shapedAmountCompareCircuit, options ...solver.Option) error {
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, options...)
	}
	for _, tc := range []shapedAmountCompareCircuit{{0, 0, 1, inputs}, {max, max, 1, inputs}, {max, 0, 0, inputs}, {0, max, 1, inputs}, {new(big.Int).Lsh(big.NewInt(1), 67), max, 1, inputs}} {
		if err := solve(&tc); err != nil {
			t.Fatal(err)
		}
		tc.Result = 1 - tc.Result.(int)
		if solve(&tc) == nil {
			t.Fatal("incorrect wide comparison accepted")
		}
	}
	called := false
	forge := func(field *big.Int, in, out []*big.Int) error {
		called = true
		if err := shapedAmountComparisonHint(field, in, out); err != nil {
			return err
		}
		out[0].Sub(out[0], offset)
		out[1].Add(out[1], big.NewInt(1))
		return nil
	}
	err = solve(&shapedAmountCompareCircuit{1, 0, 1, inputs}, solver.OverrideHint(solver.GetHintID(shapedAmountComparisonHint), forge), hintattack.SkipMissingLookupQueries(t))
	if !called {
		t.Fatal("forgery did not execute")
	}
	hintattack.RequireConstraintRejection(t, err)
}
