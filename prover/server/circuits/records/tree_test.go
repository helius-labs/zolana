package records_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
)

type rootCircuit struct {
	Root, Leaf frontend.Variable
	Path       records.QuadPath
}

func (c *rootCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Path.Root(api, c.Leaf), c.Root)
	return nil
}

// Every digit of every level places the leaf where the host tree keeps it.
func TestQuadPathFoldsTheHostTree(t *testing.T) {
	members := ringrecords.New(t)
	for m := int64(1); m <= 20; m++ {
		members.Apply(t, ringrecords.Entry{Member: big.NewInt(m * 10), Mask: big.NewInt(1), Value: big.NewInt(1), EscrowKey: big.NewInt(0)})
	}
	root := members.Root()
	for _, member := range []int64{10, 20, 30, 40, 50, 160, 170, 200} {
		opening := members.Opening(big.NewInt(member))
		assignment := &rootCircuit{Root: root, Leaf: opening.Record.Hash(t), Path: opening.Path.Wires()}
		if err := test.IsSolved(&rootCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("member %d at %d: %v", member, opening.Path.Index, err)
		}
	}
	// An empty leaf opens under the same root, its digits reach the top levels.
	for _, index := range []uint64{21, 1 << 18, 2 << 18, 3 << 18, records.Capacity - 1} {
		assignment := &rootCircuit{Root: root, Leaf: 0, Path: members.Path(index).Wires()}
		if err := test.IsSolved(&rootCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("empty leaf %d: %v", index, err)
		}
	}
}

func TestQuadPathRejectsAnotherIndex(t *testing.T) {
	members := ringrecords.New(t)
	members.Apply(t, ringrecords.Entry{Member: big.NewInt(10), Mask: big.NewInt(1), Value: big.NewInt(1), EscrowKey: big.NewInt(0)})
	opening := members.Opening(big.NewInt(10))
	for _, tc := range []struct {
		name   string
		index  *big.Int
		frames []string
	}{
		{"a neighbour sharing the siblings", big.NewInt(2), []string{"[assertIsEqual]", "records_test.(*rootCircuit).Define"}},
		{"the index plus the capacity", new(big.Int).Add(big.NewInt(1), big.NewInt(records.Capacity)), []string{"[ToBinary]", "records.QuadPath.digits"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := opening.Path.Wires()
			path.Index = tc.index
			err := test.IsSolved(&rootCircuit{}, &rootCircuit{Root: members.Root(), Leaf: opening.Record.Hash(t), Path: path}, ecc.BN254.ScalarField())
			refusal.Require(t, err, tc.frames...)
		})
	}
}

type presentCount struct {
	Root, Member frontend.Variable
	Opening      records.QuadRecordOpening
}

func (c *presentCount) Define(api frontend.API) error {
	c.Opening.AssertPresent(api, 1, c.Root, c.Member)
	return nil
}

type memberCount struct {
	Root, Member frontend.Variable
	Opening      records.QuadOpening
}

func (c *memberCount) Define(api frontend.API) error {
	c.Opening.Resolve(api, 1, c.Root, c.Member)
	return nil
}

// The policy, deposit and merge budgets assume these opening costs.
func TestOpeningConstraintCounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		circuit frontend.Circuit
		pinned  int
	}{
		{"present", &presentCount{}, 3399},
		{"member", &memberCount{}, 3677},
	} {
		if got := ringkey.Compile(t, tc.circuit).GetNbConstraints(); got != tc.pinned {
			t.Errorf("%s opening constraints=%d, pinned %d", tc.name, got, tc.pinned)
		}
	}
}
