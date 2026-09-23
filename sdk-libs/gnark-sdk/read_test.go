package gnarksdk_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
	spp "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
)

type readCircuit struct {
	Read          gnarksdk.UtxoRead
	UtxoHash      frontend.Variable `gnark:",public"`
	UtxoRoot      frontend.Variable `gnark:",public"`
	Nullifier     frontend.Variable `gnark:",public"`
	NullifierRoot frontend.Variable `gnark:",public"`
}

func (c *readCircuit) Define(api frontend.API) error {
	c.Read.Assert(api, c.UtxoHash, c.UtxoRoot, c.Nullifier, c.NullifierRoot)
	return nil
}

type readFixture struct {
	utxoHash      *big.Int
	nullifier     *big.Int
	state         protocol.StateTreeWitness
	nullifierTree *protocol.NullifierTree
	nonInclusion  protocol.NonInclusionWitness
}

// newReadFixture puts the sample UTXO in a state tree next to another leaf and
// builds a nullifier tree whose low element for the UTXO's nullifier is
// neither the tree's first element nor bounded by the domain's upper bound.
func newReadFixture(t *testing.T) readFixture {
	t.Helper()
	utxo := sampleUtxo()
	utxoHash := must(t)(protocol.UtxoHash(utxo, big.NewInt(2)))
	nullifier := must(t)(protocol.Nullifier(utxoHash, utxo.Blinding, new(big.Int)))

	_, stateProofs, err := protocol.BuildSparseStateTree(map[uint64]*big.Int{
		3: big.NewInt(7),
		5: utxoHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	nullifierTree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	above := new(big.Int).Add(nullifier, big.NewInt(5))
	if !protocol.InNullifierDomain(above) {
		t.Fatalf("fixture nullifier %s leaves no room above it", nullifier)
	}
	for _, value := range []*big.Int{big.NewInt(1000), above} {
		if err := nullifierTree.Insert(value); err != nil {
			t.Fatal(err)
		}
	}
	nonInclusion, err := nullifierTree.NonInclusionWitness(nullifier)
	if err != nil {
		t.Fatal(err)
	}
	if nonInclusion.LowValue.Cmp(big.NewInt(1000)) != 0 || nonInclusion.NextValue.Cmp(above) != 0 {
		t.Fatalf("fixture low element brackets (%s, %s)", nonInclusion.LowValue, nonInclusion.NextValue)
	}

	return readFixture{
		utxoHash:      utxoHash,
		nullifier:     nullifier,
		state:         stateProofs[5],
		nullifierTree: nullifierTree,
		nonInclusion:  nonInclusion,
	}
}

func (f readFixture) assignment() *readCircuit {
	var statePath [spp.StateTreeHeight]frontend.Variable
	for i, element := range f.state.PathElements {
		statePath[i] = element
	}
	var lowPath [spp.NullifierTreeHeight]frontend.Variable
	for i, element := range f.nonInclusion.PathElements {
		lowPath[i] = element
	}
	return &readCircuit{
		Read: gnarksdk.UtxoRead{
			StatePathElements:        statePath,
			StatePathIndex:           f.state.PathIndex,
			NullifierLowValue:        f.nonInclusion.LowValue,
			NullifierNextValue:       f.nonInclusion.NextValue,
			NullifierLowPathElements: lowPath,
			NullifierLowPathIndex:    f.nonInclusion.LowIndex,
		},
		UtxoHash:      f.utxoHash,
		UtxoRoot:      f.state.Root,
		Nullifier:     f.nullifier,
		NullifierRoot: f.nonInclusion.Root,
	}
}

func TestUtxoReadAcceptsUnspentUtxo(t *testing.T) {
	cs := compile(t, &readCircuit{})
	assertAccepted(t, cs, newReadFixture(t).assignment())
}

func TestUtxoReadRejectsWrongStateOrRoots(t *testing.T) {
	cs := compile(t, &readCircuit{})
	fixture := newReadFixture(t)
	for name, mutate := range map[string]func(*readCircuit){
		"utxo hash":        func(c *readCircuit) { c.UtxoHash = plusOne(fixture.utxoHash) },
		"state path index": func(c *readCircuit) { c.Read.StatePathIndex = fixture.state.PathIndex + 1 },
		"utxo root":        func(c *readCircuit) { c.UtxoRoot = plusOne(fixture.state.Root) },
		"nullifier root":   func(c *readCircuit) { c.NullifierRoot = plusOne(fixture.nonInclusion.Root) },
		"low path index":   func(c *readCircuit) { c.Read.NullifierLowPathIndex = fixture.nonInclusion.LowIndex + 1 },
		"low next value":   func(c *readCircuit) { c.Read.NullifierNextValue = plusOne(fixture.nonInclusion.NextValue) },
	} {
		t.Run(name, func(t *testing.T) {
			assignment := fixture.assignment()
			mutate(assignment)
			assertRejected(t, cs, assignment)
		})
	}
}

// A nullifier the tree holds is rejected even with a valid low-leaf path: the
// low leaf's own value and its next value are both tree elements, and the
// bracket is strict at both ends.
func TestUtxoReadRejectsNullifierInTree(t *testing.T) {
	cs := compile(t, &readCircuit{})
	fixture := newReadFixture(t)
	for name, member := range map[string]*big.Int{
		"low value":  fixture.nonInclusion.LowValue,
		"next value": fixture.nonInclusion.NextValue,
	} {
		t.Run(name, func(t *testing.T) {
			assignment := fixture.assignment()
			assignment.Nullifier = member
			assertRejected(t, cs, assignment)
		})
	}
}

// Once the nullifier enters the tree, the read proven before the insert fails
// against the new root and no new non-inclusion proof exists. Under the old
// root it still verifies, which is why the program also checks the nullifier
// PDA.
func TestUtxoReadRejectsSpentUtxoUnderNewRoot(t *testing.T) {
	cs := compile(t, &readCircuit{})
	fixture := newReadFixture(t)
	if err := fixture.nullifierTree.Insert(fixture.nullifier); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.nullifierTree.NonInclusionWitness(fixture.nullifier); err == nil {
		t.Fatal("non-inclusion proof built for an inserted nullifier")
	}

	assignment := fixture.assignment()
	assignment.NullifierRoot = fixture.nullifierTree.Root()
	assertRejected(t, cs, assignment)
}
