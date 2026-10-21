package merge

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
	mergecircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	customring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
)

type presentCircuit struct {
	Root, Member frontend.Variable
	Opening      records.QuadRecordOpening
}

func (c *presentCircuit) Define(api frontend.API) error {
	c.Opening.AssertPresent(api, 1, c.Root, c.Member)
	return nil
}

// The request's flat path lands on the circuit's levels and child order.
func TestRingWitnessOpensTheMemberRecord(t *testing.T) {
	members := ringrecords.New(t)
	for m := int64(1); m <= 21; m++ {
		members.Apply(t, ringrecords.Entry{Member: big.NewInt(m * 10), Mask: big.NewInt(1), Value: big.NewInt(1), EscrowKey: big.NewInt(0)})
	}
	// Index 21 has a nonzero digit on levels 0, 1 and 2.
	member := big.NewInt(210)
	opened := members.Opening(member)
	if opened.Path.Index != 21 {
		t.Fatalf("member at %d", opened.Path.Index)
	}
	p := sampleParams()
	p.CircuitType = common.MergeRingCircuitType
	p.MemberRecord = &customring.RecordOpening{
		Next: customring.Field{Int: opened.Record.Next}, Lists: opened.Record.Lists.Uint64(),
		EscrowKey: customring.Field{Int: opened.Record.EscrowKey}, Index: opened.Path.Index,
	}
	for _, row := range opened.Path.Siblings {
		for _, sibling := range row {
			p.MemberRecord.Path = append(p.MemberRecord.Path, customring.Field{Int: sibling})
		}
	}
	if err := p.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	assignment, err := p.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	opening := assignment.(*mergecircuit.RingCircuit).MemberRecord
	if err := test.IsSolved(&presentCircuit{}, &presentCircuit{Root: members.Root(), Member: member, Opening: opening}, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// An anonymous ring merge binds the zero root its ring program forwards and reads no record, a carried record is refused.
func TestAnonymousRingMergeCarriesNoMemberRecord(t *testing.T) {
	p := sampleParams()
	p.CircuitType = common.MergeRingCircuitType
	p.Anonymous, p.RegisteredCiphertextHash, p.MemberRegistryRoot = true, nil, big.NewInt(0)
	if p.ValidateShape() == nil {
		t.Fatal("an anonymous merge carried a member record")
	}
	wire, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(wire, new(MergeParameters)) == nil {
		t.Fatal("decoded an anonymous merge carrying a member record")
	}
	p.MemberRecord = nil
	if wire, err = json.Marshal(p); err != nil {
		t.Fatal(err)
	}
	var decoded MergeParameters
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	assignment, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	if record := assignment.(*mergecircuit.RingCircuit).MemberRecord; record.Next != 0 || record.Path.Siblings[0][0] != 0 {
		t.Fatalf("the unread record assigned %v", record)
	}
}

// The ring program forwards a zero root exactly on an anonymous merge, any other pairing has no statement.
func TestRingMergeRootFollowsTheMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		root      int64
	}{
		{"an escrow merge with a zero root", false, 0},
		{"an anonymous merge naming a root", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleParams()
			p.CircuitType, p.MemberRegistryRoot = common.MergeRingCircuitType, big.NewInt(tc.root)
			if tc.anonymous {
				p.Anonymous, p.RegisteredCiphertextHash, p.MemberRecord = true, nil, nil
			}
			if p.ValidateShape() == nil {
				t.Fatal("a root the mode refuses passed")
			}
		})
	}
}
