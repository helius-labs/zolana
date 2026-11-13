package lookup

import (
	"math/big"
	"strings"
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

// A late query or row must stop compilation before an unchecked proof can exist.
type lateTableCircuit struct {
	Value  frontend.Variable
	Insert bool `gnark:"-"`
}

func (c *lateTableCircuit) Define(api frontend.API) error {
	table := New(api, 1)
	table.Insert([]frontend.Variable{1})
	api.Compiler().Defer(func(api frontend.API) error {
		if c.Insert {
			table.Insert([]frontend.Variable{c.Value})
		} else {
			table.Lookup(c.Value)
		}
		return nil
	})
	return nil
}

func TestLateTableMutationRejectsCompilation(t *testing.T) {
	for _, insert := range []bool{false, true} {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lateTableCircuit{Insert: insert})
		if err == nil || !strings.Contains(err.Error(), "lookup table already finalized") {
			t.Fatalf("late table mutation: %v", err)
		}
	}
}

// The lookup hint reads only the rows inserted before the query.
type insertAfterLookupCircuit struct {
	Index frontend.Variable
}

func (c *insertAfterLookupCircuit) Define(api frontend.API) error {
	table := New(api, 1)
	table.Insert([]frontend.Variable{10})
	table.Lookup(c.Index)
	table.Insert([]frontend.Variable{20})
	return nil
}

func TestInsertAfterLookupRejectsCompilation(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &insertAfterLookupCircuit{})
	if err == nil || !strings.Contains(err.Error(), "lookup table already queried") {
		t.Fatalf("insert after lookup: %v", err)
	}
}

// Writes to a caller slice or pointer constant must not change the deferred relation.
type callerWriteCircuit struct {
	A, B frontend.Variable
	Mode string `gnark:"-"`
}

func (c *callerWriteCircuit) Define(api frontend.API) error {
	table := New(api, 1)
	switch c.Mode {
	case "row":
		row := []frontend.Variable{c.A}
		table.Insert(row)
		row[0] = c.B
		api.AssertIsEqual(table.Lookup(0)[0], c.A)
	case "result":
		table.Insert([]frontend.Variable{c.A})
		out := table.Lookup(0)
		result := out[0]
		out[0] = c.B
		api.AssertIsEqual(result, c.A)
	case "constant":
		entry := big.NewInt(1)
		table.Insert([]frontend.Variable{entry})
		entry.SetInt64(2)
		api.AssertIsEqual(table.Lookup(0)[0], 1)
	case "index":
		table.Insert([]frontend.Variable{1})
		table.Insert([]frontend.Variable{2})
		index := big.NewInt(0)
		result := table.Lookup(index)[0]
		index.SetInt64(1)
		api.AssertIsEqual(result, 1)
	}
	return nil
}

func TestCallerWritesDoNotAliasTheTable(t *testing.T) {
	for _, mode := range []string{"row", "result", "constant", "index"} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &callerWriteCircuit{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(&callerWriteCircuit{A: 1, B: 2}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
	}
}

// A lookup into a table without rows can never be satisfied.
type emptyTableCircuit struct {
	Index frontend.Variable
}

func (c *emptyTableCircuit) Define(api frontend.API) error {
	New(api, 1).Lookup(c.Index)
	return nil
}

func TestEmptyTableLookupRejectsCompilation(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyTableCircuit{})
	if err == nil || !strings.Contains(err.Error(), "lookup table has no rows") {
		t.Fatalf("empty table lookup: %v", err)
	}
}
