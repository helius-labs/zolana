package registry

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The sentinel-only root every fresh registry starts from, pinned by Rust and TypeScript too.
const EmptyRootHex = "27472d6d1303748e8179957ca7c41499a13516f156088e4550b969f2509af21c"

func TestEmptyRootIsPinned(t *testing.T) {
	got := fmt.Sprintf("%064x", spptest.NewMemberRegistry(t, Height).Root())
	if got != EmptyRootHex {
		t.Fatalf("empty root %s, pinned %s", got, EmptyRootHex)
	}
}

func TestZeroNullifierPkIsThePoseidonOfZero(t *testing.T) {
	if got := spptest.MustNullifierPk(t, big.NewInt(0)); got.Cmp(spptest.ZeroNullifierPk()) != 0 {
		t.Fatalf("Poseidon(0) is %x", got)
	}
}

type openingCircuit struct {
	Compact   bool `gnark:"-"`
	Cond      frontend.Variable
	Root      frontend.Variable
	Member    frontend.Variable
	Lists     frontend.Variable
	EscrowKey frontend.Variable
	Opening   MemberOpening
}

func (c *openingCircuit) Define(api frontend.API) error {
	resolve := c.Opening.Resolve
	if c.Compact {
		resolve = c.Opening.ResolveCompact
	}
	lists, escrowKey := resolve(api, c.Cond, c.Root, c.Member)
	api.AssertIsEqual(lists, c.Lists)
	api.AssertIsEqual(escrowKey, c.EscrowKey)
	return nil
}

// pathVars zero-fills a short or missing path.
func pathVars(path []big.Int) [Height]frontend.Variable {
	var out [Height]frontend.Variable
	for i := range out {
		out[i] = 0
	}
	for i := range path {
		out[i] = new(big.Int).Set(&path[i])
	}
	return out
}

func openingWires(w spptest.MemberOpeningWitness) MemberOpening {
	o := MemberOpening{Present: 0, LowMember: 0, LowNext: 0, LowLists: 0, LowEscrow: 0}
	o.Index, o.Path = w.Index, pathVars(w.Path)
	o.Next, o.Lists, o.EscrowKey = 0, 0, 0
	if w.Present {
		o.Present, o.Next, o.Lists, o.EscrowKey = 1, w.Record.Next, w.Record.Lists, w.Record.EscrowKey
		return o
	}
	o.LowMember, o.LowNext, o.LowLists, o.LowEscrow = w.Record.Member, w.Record.Next, w.Record.Lists, w.Record.EscrowKey
	return o
}

func TestMemberOpeningResolvesPresentAndAbsentMembers(t *testing.T) {
	members := spptest.NewMemberRegistry(t, Height)
	alice, bob, carol := big.NewInt(0x0a), big.NewInt(0x0b), big.NewInt(0x0c)
	members.Update(t, alice, big.NewInt(0b101), big.NewInt(0x5e))
	members.Update(t, carol, big.NewInt(0b010), big.NewInt(0))
	assignment := func(member *big.Int) *openingCircuit {
		opening := members.Opening(member)
		c := &openingCircuit{Cond: 1, Root: members.Root(), Member: member, Lists: 0, EscrowKey: 0, Opening: openingWires(opening)}
		if opening.Present {
			c.Lists, c.EscrowKey = opening.Record.Lists, opening.Record.EscrowKey
		}
		return c
	}
	tests := []struct {
		name   string
		change func(*openingCircuit)
		passes bool
	}{
		{"present member", func(*openingCircuit) {}, true},
		{"absent member", func(c *openingCircuit) { *c = *assignment(bob) }, true},
		{"absent member below every record", func(c *openingCircuit) { *c = *assignment(big.NewInt(1)) }, true},
		{"absent member above every record", func(c *openingCircuit) { *c = *assignment(big.NewInt(0xff)) }, true},
		{"wrong root", func(c *openingCircuit) { c.Root = big.NewInt(1) }, false},
		{"lists tampered", func(c *openingCircuit) { c.Opening.Lists, c.Lists = big.NewInt(0b111), big.NewInt(0b111) }, false},
		{"escrow key tampered", func(c *openingCircuit) { c.Opening.EscrowKey, c.EscrowKey = big.NewInt(1), big.NewInt(1) }, false},
		{"present member claimed absent", func(c *openingCircuit) {
			absent := assignment(alice)
			absent.Opening.Present, absent.Opening.Lists, absent.Opening.EscrowKey = 0, 0, 0
			absent.Lists, absent.EscrowKey = 0, 0
			*c = *absent
		}, false},
		{"absent member with lists", func(c *openingCircuit) {
			*c = *assignment(bob)
			c.Opening.Lists, c.Lists = big.NewInt(1), big.NewInt(1)
		}, false},
		{"absent member with an escrow key", func(c *openingCircuit) {
			*c = *assignment(bob)
			c.Opening.EscrowKey, c.EscrowKey = big.NewInt(1), big.NewInt(1)
		}, false},
		{"absent member outside the low bracket", func(c *openingCircuit) {
			*c = *assignment(bob)
			c.Member = big.NewInt(0xff)
		}, false},
		{"absent member equal to the low record", func(c *openingCircuit) {
			*c = *assignment(bob)
			c.Member = alice
		}, false},
		{"absent member equal to the low next", func(c *openingCircuit) {
			*c = *assignment(bob)
			c.Member = carol
		}, false},
		{"another member's record", func(c *openingCircuit) { c.Member = bob }, false},
		{"present flag not boolean", func(c *openingCircuit) { c.Opening.Present = 2 }, false},
		{"index alias above the capacity", func(c *openingCircuit) {
			c.Opening.Index = new(big.Int).Add(new(big.Int).SetUint64(c.Opening.Index.(uint64)), new(big.Int).Lsh(big.NewInt(1), Height))
		}, false},
		{"condition off ignores the opening", func(c *openingCircuit) {
			c.Cond, c.Root, c.Lists, c.EscrowKey = 0, big.NewInt(1), 0, 0
		}, true},
		{"condition off still needs a boolean flag", func(c *openingCircuit) {
			c.Cond, c.Opening.Present = 0, 2
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := assignment(alice)
			tt.change(c)
			for _, compact := range []bool{false, true} {
				c.Compact = compact
				err := test.IsSolved(&openingCircuit{Compact: compact}, c, ecc.BN254.ScalarField())
				if (err == nil) != tt.passes {
					t.Fatalf("compact=%v passes=%v, solve=%v", compact, tt.passes, err)
				}
			}
		})
	}
}

type presentCircuit struct {
	Cond    frontend.Variable
	Root    frontend.Variable
	Member  frontend.Variable
	Opening RecordOpening
}

func (c *presentCircuit) Define(api frontend.API) error {
	c.Opening.AssertPresent(api, c.Cond, c.Root, c.Member)
	return nil
}

func TestRecordOpeningRequiresTheRecord(t *testing.T) {
	members := spptest.NewMemberRegistry(t, Height)
	alice := big.NewInt(0x0a)
	members.Update(t, alice, big.NewInt(1), big.NewInt(0x5e))
	assignment := func() *presentCircuit {
		opening := members.Opening(alice)
		return &presentCircuit{Cond: 1, Root: members.Root(), Member: alice, Opening: openingWires(opening).RecordOpening}
	}
	tests := []struct {
		name   string
		change func(*presentCircuit)
		passes bool
	}{
		{"registered member", func(*presentCircuit) {}, true},
		{"absent member", func(c *presentCircuit) { c.Member = big.NewInt(0x0b) }, false},
		{"wrong escrow key", func(c *presentCircuit) { c.Opening.EscrowKey = big.NewInt(1) }, false},
		{"condition off", func(c *presentCircuit) { c.Cond, c.Member = 0, big.NewInt(0x0b) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := assignment()
			tt.change(c)
			err := test.IsSolved(&presentCircuit{}, c, ecc.BN254.ScalarField())
			if (err == nil) != tt.passes {
				t.Fatalf("passes=%v, solve=%v", tt.passes, err)
			}
		})
	}
}
