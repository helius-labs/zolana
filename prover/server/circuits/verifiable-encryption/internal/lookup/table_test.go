package lookup

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type lookupCircuit struct {
	Index, Value frontend.Variable
	Queries      int `gnark:"-"`
}

func (v *lookupCircuit) Define(api frontend.API) error {
	t := New(api, 1)
	for i := 0; i < 16; i++ {
		t.Insert([]frontend.Variable{7*i + 1})
	}
	for i := 0; i < v.Queries; i++ {
		api.AssertIsEqual(t.Lookup(v.Index)[0], v.Value)
	}
	return nil
}
func TestLookupRejectsForgery(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupCircuit{Queries: 2})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(index, value frontend.Variable, opts ...solver.Option) error {
		w, err := frontend.NewWitness(&lookupCircuit{Index: index, Value: value}, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		return cs.IsSolved(w, opts...)
	}
	if err := solve(3, 22); err != nil {
		t.Fatal(err)
	}
	for _, v := range [][2]int{{3, 23}, {16, 0}, {-1, 0}} {
		if solve(v[0], v[1]) == nil {
			t.Fatal("invalid lookup accepted", v)
		}
	}
	for _, h := range []solver.Hint{RowLookupHint, RowCountHint} {
		called := false
		poison := func(q *big.Int, in, out []*big.Int) error {
			called = true
			if err := h(q, in, out); err != nil {
				return err
			}
			out[0].Add(out[0], big.NewInt(1))
			return nil
		}
		if solve(3, 22, solver.OverrideHint(solver.GetHintID(h), poison)) == nil || !called {
			t.Fatal("lookup forged hint not rejected", solver.GetHintName(h))
		}
	}
}
