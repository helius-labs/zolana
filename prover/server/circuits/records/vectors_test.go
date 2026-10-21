package records_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
)

// The circuit and the host twin open the Rust registry's records and empty tree.
func TestQuadOpeningsMatchRustVectors(t *testing.T) {
	v := ringrecords.ReadVector(t)
	if root := ringrecords.New(t).Root(); root.Cmp(v.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", root, v.EmptyRoot.Int)
	}
	for _, o := range v.Openings {
		opening := ringrecords.Opening{Present: o.Present, Record: o.Record.Record(), Path: o.Path.Path(t)}
		c := &resolveCircuit{Cond: 1, Root: o.Root.Int, Member: o.Member.Int, Lists: 0, EscrowKey: 0, Opening: opening.Wires()}
		if o.Present {
			c.Lists, c.EscrowKey = opening.Record.Lists, opening.Record.EscrowKey
		}
		if err := test.IsSolved(&resolveCircuit{}, c, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("member %x present=%v: %v", o.Member.Int, o.Present, err)
		}
	}
}
