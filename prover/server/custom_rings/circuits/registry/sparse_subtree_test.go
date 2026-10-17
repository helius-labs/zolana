package registry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type sparseBatchCircuit struct {
	Root                           frontend.Variable
	Members, Active, Lists, Escrow [3]frontend.Variable
	Openings                       [3]MemberOpening
	Frontier                       SparseSubtree
}

func (c *sparseBatchCircuit) Define(api frontend.API) error {
	b := NewSparseSubtreeBatch(api, c.Root, &c.Frontier)
	for i, opening := range c.Openings {
		lists, escrow := b.Resolve(api, opening, c.Active[i], c.Members[i])
		api.AssertIsEqual(lists, c.Lists[i])
		api.AssertIsEqual(escrow, c.Escrow[i])
	}
	b.Check(api)
	return nil
}

func TestSparseSubtreeAuthentication(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &sparseBatchCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	tree := spptest.NewMemberRegistry(t, Height)
	for i := int64(1); i <= 20; i++ {
		tree.Update(t, big.NewInt(i*10), big.NewInt(i), big.NewInt(i+100))
	}
	build := func(members [3]int64) (*sparseBatchCircuit, []SparseOpening) {
		w := &sparseBatchCircuit{Root: tree.Root()}
		var openings []SparseOpening
		for i, member := range members {
			m := big.NewInt(member)
			o := tree.Opening(m)
			w.Members[i], w.Active[i], w.Openings[i] = m, 1, openingWires(o)
			w.Lists[i], w.Escrow[i] = 0, 0
			if o.Present {
				w.Lists[i], w.Escrow[i] = o.Record.Lists, o.Record.EscrowKey
			}
			openings = append(openings, SparseOpening{Index: o.Index, Leaf: o.Record.Hash(t), Path: o.Path})
		}
		return w, openings
	}
	check := func(w *sparseBatchCircuit, valid bool) {
		t.Helper()
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(witness)
		if (err == nil) != valid {
			t.Fatalf("valid=%v: %v", valid, err)
		}
	}
	// Present, absent and repeated subjects. The subtree is above index zero.
	w, openings := build([3]int64{80, 95, 80})
	w.Frontier, err = BuildSparseSubtree(openings)
	if err != nil {
		t.Fatal(err)
	}
	check(w, true)
	for _, attack := range []struct {
		name   string
		change func(*sparseBatchCircuit)
	}{
		{"opaque ancestor", func(w *sparseBatchCircuit) { w.Frontier.Expanded[0] = 0 }},
		{"opaque leaf parent", func(w *sparseBatchCircuit) { w.Frontier.Expanded[3] = 0 }},
		{"nonboolean expansion", func(w *sparseBatchCircuit) { w.Frontier.Expanded[0] = 2 }},
		{"wrong node", func(w *sparseBatchCircuit) { w.Frontier.Nodes[7] = 123 }},
		{"forged lists", func(w *sparseBatchCircuit) { w.Openings[0].Lists = 7; w.Lists[0] = 7 }},
		{"forged escrow", func(w *sparseBatchCircuit) { w.Openings[0].EscrowKey = 7; w.Escrow[0] = 7 }},
		{"different prefix", func(w *sparseBatchCircuit) { w.Openings[0].Index = 0 }},
		{"wrong root", func(w *sparseBatchCircuit) { w.Root = 123 }},
		{"wrong upper path", func(w *sparseBatchCircuit) { w.Openings[2].Path[7] = 123 }},
		{"index overflow", func(w *sparseBatchCircuit) { w.Openings[0].Index = 1 << Height }},
	} {
		t.Run(attack.name, func(t *testing.T) { bad := *w; attack.change(&bad); check(&bad, false) })
	}
	// Inactive batches need no authenticated registry records.
	empty := *w
	empty.Frontier, err = BuildSparseSubtree(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range empty.Active {
		empty.Active[i], empty.Lists[i], empty.Escrow[i] = 0, 0, 0
	}
	check(&empty, true)
	_, scattered := build([3]int64{10, 80, 90})
	if _, err := BuildSparseSubtree(scattered); err == nil {
		t.Fatal("scattered records accepted by builder")
	}
	bad := *w
	bad.Openings[0] = openingWires(tree.Opening(big.NewInt(10)))
	bad.Members[0], bad.Lists[0], bad.Escrow[0] = 10, 1, 101
	check(&bad, false)
	conflicting := append([]SparseOpening{}, openings...)
	conflicting[2].Leaf = big.NewInt(1)
	if _, err := BuildSparseSubtree(conflicting); err == nil {
		t.Fatal("conflicting record accepted")
	}
	// A host omission must also fail in the circuit.
	missing, all := build([3]int64{80, 90, 100})
	missing.Frontier, err = BuildSparseSubtree(all[:1])
	if err != nil {
		t.Fatal(err)
	}
	check(missing, false)
}
