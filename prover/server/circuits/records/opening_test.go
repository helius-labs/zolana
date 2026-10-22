package records_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
)

type resolveCircuit struct {
	Cond, Root, Member, Lists, EscrowKey frontend.Variable
	Opening                              records.QuadOpening
}

func (c *resolveCircuit) Define(api frontend.API) error {
	lists, escrowKey := c.Opening.Resolve(api, c.Cond, c.Root, c.Member)
	api.AssertIsEqual(lists, c.Lists)
	api.AssertIsEqual(escrowKey, c.EscrowKey)
	return nil
}

var (
	alice = big.NewInt(0x0a)
	bob   = big.NewInt(0x0b)
	carol = big.NewInt(0x0c)
)

// openingRegistry holds alice with lists and a key and carol with lists, bob is absent between them.
func openingRegistry(t *testing.T) *ringrecords.Registry {
	t.Helper()
	members := ringrecords.New(t)
	members.Apply(t, ringrecords.Entry{Member: alice, Mask: big.NewInt(0xff), Value: big.NewInt(0b101), EscrowKey: big.NewInt(0x5e)})
	members.Apply(t, ringrecords.Entry{Member: carol, Mask: big.NewInt(0xff), Value: big.NewInt(0b010), EscrowKey: big.NewInt(0)})
	return members
}

// resolveAssignment opens member honestly, the expected outputs read from the host record.
func resolveAssignment(members *ringrecords.Registry, member *big.Int) *resolveCircuit {
	opening := members.Opening(member)
	c := &resolveCircuit{Cond: 1, Root: members.Root(), Member: member, Lists: 0, EscrowKey: 0, Opening: opening.Wires()}
	if opening.Present {
		c.Lists, c.EscrowKey = opening.Record.Lists, opening.Record.EscrowKey
	}
	return c
}

func TestQuadOpeningResolvesPresentAndAbsentMembers(t *testing.T) {
	members := openingRegistry(t)
	for name, member := range map[string]*big.Int{
		"present member":                   alice,
		"absent member":                    bob,
		"absent member below every record": big.NewInt(1),
		"absent member above every record": big.NewInt(0xff),
	} {
		t.Run(name, func(t *testing.T) {
			if err := test.IsSolved(&resolveCircuit{}, resolveAssignment(members, member), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
	}
	off := resolveAssignment(members, bob)
	off.Cond, off.Root = 0, big.NewInt(1)
	if err := test.IsSolved(&resolveCircuit{}, off, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("an unset cond binds the opening: %v", err)
	}
}

// Each case changes one value of an honest opening, the named frame raises the refusal.
func TestQuadOpeningRefusals(t *testing.T) {
	members := openingRegistry(t)
	sentinel := members.Opening(big.NewInt(1))
	rootGate := []string{"gadget.AssertEqualWhen", "records.QuadOpening.Resolve"}
	emptyGate := []string{"gadget.AssertZeroWhen", "records.QuadOpening.Resolve"}
	flag := []string{"[assertIsBoolean]", "records.QuadOpening.Resolve"}
	bracket := []string{"gadget.AssertOrderedWhen", "records.QuadOpening.Resolve"}
	tests := []struct {
		name   string
		member *big.Int
		tamper func(*resolveCircuit)
		frames []string
	}{
		{"wrong root", alice, func(c *resolveCircuit) { c.Root = big.NewInt(1) }, rootGate},
		{"lists not in the record", alice, func(c *resolveCircuit) { c.Opening.Lists, c.Lists = big.NewInt(0b111), big.NewInt(0b111) }, rootGate},
		{"escrow key not in the record", alice, func(c *resolveCircuit) { c.Opening.EscrowKey, c.EscrowKey = big.NewInt(1), big.NewInt(1) }, rootGate},
		{"another member's record", alice, func(c *resolveCircuit) { c.Member = bob }, rootGate},
		{"present member through the record linking to it", alice, func(c *resolveCircuit) {
			// The sentinel links to alice, the only low record a present alice has.
			c.Opening, c.Lists, c.EscrowKey = sentinel.Wires(), 0, 0
		}, bracket},
		{"absent member with lists", bob, func(c *resolveCircuit) { c.Opening.Lists, c.Lists = big.NewInt(1), big.NewInt(1) }, emptyGate},
		{"absent member with an escrow key", bob, func(c *resolveCircuit) { c.Opening.EscrowKey, c.EscrowKey = big.NewInt(1), big.NewInt(1) }, emptyGate},
		{"absent member past the low record's next", bob, func(c *resolveCircuit) { c.Member = big.NewInt(0xff) }, bracket},
		{"absent member equal to the low record", bob, func(c *resolveCircuit) { c.Member = alice }, bracket},
		{"absent member equal to the low record's next", bob, func(c *resolveCircuit) { c.Member = carol }, bracket},
		{"present flag not boolean", alice, func(c *resolveCircuit) { c.Opening.Present = 2 }, flag},
		{"unset cond with a flag that is not boolean", alice, func(c *resolveCircuit) { c.Cond, c.Lists, c.EscrowKey, c.Opening.Present = 0, 0, 0, 2 }, flag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := resolveAssignment(members, tt.member)
			tt.tamper(c)
			refusal.Require(t, test.IsSolved(&resolveCircuit{}, c, ecc.BN254.ScalarField()), tt.frames...)
		})
	}
}

type presentCircuit struct {
	Cond, Root, Member frontend.Variable
	Opening            records.QuadRecordOpening
}

func (c *presentCircuit) Define(api frontend.API) error {
	c.Opening.AssertPresent(api, c.Cond, c.Root, c.Member)
	return nil
}

func TestQuadRecordOpeningRequiresTheRecord(t *testing.T) {
	members := openingRegistry(t)
	honest := func() *presentCircuit {
		return &presentCircuit{Cond: 1, Root: members.Root(), Member: alice, Opening: members.Opening(alice).RecordWires()}
	}
	if err := test.IsSolved(&presentCircuit{}, honest(), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	off := honest()
	off.Cond, off.Member = 0, bob
	if err := test.IsSolved(&presentCircuit{}, off, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("an unset cond binds the record: %v", err)
	}
	for name, tamper := range map[string]func(*presentCircuit){
		"absent member":    func(c *presentCircuit) { c.Member = bob },
		"wrong escrow key": func(c *presentCircuit) { c.Opening.EscrowKey = big.NewInt(1) },
	} {
		t.Run(name, func(t *testing.T) {
			c := honest()
			tamper(c)
			refusal.Require(t, test.IsSolved(&presentCircuit{}, c, ecc.BN254.ScalarField()), "gadget.AssertEqualWhen", "records.QuadRecordOpening.AssertPresent")
		})
	}
}
