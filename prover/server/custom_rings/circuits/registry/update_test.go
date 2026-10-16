package registry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// A batch item as the program encodes it, the host registry supplies the paths.
type hostItem struct {
	member, lists, escrow *big.Int
}

func updateWires(w spptest.MemberUpdateWitness) MemberUpdateWires {
	item := MemberUpdateWires{
		Member: w.Member, OldLists: w.OldLists, OldEscrowKey: w.OldEscrow, Lists: w.Lists, EscrowKey: w.EscrowKey,
		RecordUpdate: RecordUpdate{Exists: 0, Next: w.Next, Index: w.Index, Path: pathVars(w.Path),
			LowMember: 0, LowNext: 0, LowLists: 0, LowEscrow: 0, LowIndex: 0, LowPath: pathVars(nil)},
	}
	if w.Exists {
		item.Exists = 1
		return item
	}
	item.LowMember, item.LowNext, item.LowLists, item.LowEscrow = w.Low.Member, w.Low.Next, w.Low.Lists, w.Low.EscrowKey
	item.LowIndex, item.LowPath = w.LowIndex, pathVars(w.LowPath)
	return item
}

func zeroItem() MemberUpdateWires {
	return MemberUpdateWires{Member: 0, OldLists: 0, OldEscrowKey: 0, Lists: 0, EscrowKey: 0,
		RecordUpdate: RecordUpdate{Exists: 0, Next: 0, Index: 0, Path: pathVars(nil), LowMember: 0, LowNext: 0, LowLists: 0, LowEscrow: 0, LowIndex: 0, LowPath: pathVars(nil)}}
}

// batchAssignment applies the items to the registry and binds the statement.
func batchAssignment(t *testing.T, members *spptest.MemberRegistry, items []hostItem) (*UpdateMembersCircuit, []spptest.MemberUpdateWitness) {
	t.Helper()
	c := &UpdateMembersCircuit{OldRoot: members.Root(), ItemCount: len(items)}
	witnesses := make([]spptest.MemberUpdateWitness, len(items))
	for i := range c.Items {
		c.Items[i] = zeroItem()
	}
	for i, item := range items {
		witnesses[i] = members.Update(t, item.member, item.lists, item.escrow)
		c.Items[i] = updateWires(witnesses[i])
	}
	c.NewRoot = members.Root()
	bindBatch(t, c)
	return c, witnesses
}

// Mirrors UpdateMembersPublicInput, disabled items hash as zeros.
func bindBatch(t *testing.T, c *UpdateMembersCircuit) {
	t.Helper()
	count := int(spptest.AsBigInt(c.ItemCount).Int64())
	items := []*big.Int{spptest.AsBigInt(c.ItemCount)}
	for i, item := range c.Items {
		for _, value := range []frontend.Variable{item.Member, item.OldLists, item.OldEscrowKey, item.Lists, item.EscrowKey, item.Index} {
			if i < count {
				items = append(items, spptest.AsBigInt(value))
			} else {
				items = append(items, big.NewInt(0))
			}
		}
	}
	chain := []*big.Int{spptest.AsBigInt(c.OldRoot), spptest.AsBigInt(c.NewRoot), spptest.MustHashChain(t, items)}
	c.PublicInputHash = spptest.MustHashChain(t, chain)
}

var batchCs constraint.ConstraintSystem

func batchSystem(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	if batchCs == nil {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &UpdateMembersCircuit{}, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		batchCs = cs
	}
	return batchCs
}

func solveBatch(t *testing.T, c *UpdateMembersCircuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return batchSystem(t).IsSolved(witness)
}

func TestUpdateMembersCommitmentShape(t *testing.T) {
	cs := batchSystem(t)
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Fatalf("commitments %v", cs.GetCommitments())
	}
	t.Logf("update_members: %d constraints", cs.GetNbConstraints())
}

func TestUpdateMembersAppliesABatchInOrder(t *testing.T) {
	members := spptest.NewMemberRegistry(t, Height)
	members.Update(t, big.NewInt(0x40), big.NewInt(1), big.NewInt(0))
	items := []hostItem{
		{big.NewInt(0x10), big.NewInt(0b11), big.NewInt(0)},
		{big.NewInt(0x40), big.NewInt(0b100), big.NewInt(0x5e)},
		{big.NewInt(0x50), big.NewInt(0), big.NewInt(0x5f)},
		{big.NewInt(0x60), big.NewInt(1), big.NewInt(0)},
	}
	c, _ := batchAssignment(t, members, items)
	if err := solveBatch(t, c); err != nil {
		t.Fatal(err)
	}
	full := spptest.NewMemberRegistry(t, Height)
	var all []hostItem
	for i := range MaxBatch {
		all = append(all, hostItem{big.NewInt(int64(0x100 + i)), big.NewInt(int64(i)), big.NewInt(0)})
	}
	c, _ = batchAssignment(t, full, all)
	if err := solveBatch(t, c); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMembersRejectsTamperedBatches(t *testing.T) {
	seed := func() (*spptest.MemberRegistry, []hostItem) {
		members := spptest.NewMemberRegistry(t, Height)
		members.Update(t, big.NewInt(0x40), big.NewInt(1), big.NewInt(0))
		return members, []hostItem{
			{big.NewInt(0x10), big.NewInt(0b11), big.NewInt(0)},
			{big.NewInt(0x40), big.NewInt(0b100), big.NewInt(0x5e)},
		}
	}
	tests := []struct {
		name   string
		tamper func(*UpdateMembersCircuit, []spptest.MemberUpdateWitness)
		// rebind recomputes the statement over the tampered items
		rebind bool
	}{
		{"new root does not follow the items", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.NewRoot = big.NewInt(1)
		}, true},
		{"item hidden from the statement", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[1].Lists = big.NewInt(0b101)
		}, false},
		{"disabled item changes the root", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.ItemCount = 1
		}, true},
		{"items applied out of order", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0], c.Items[1] = c.Items[1], c.Items[0]
		}, true},
		{"insert into the wrong gap", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].Member = big.NewInt(0x41)
		}, true},
		{"insert claims old lists", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].OldLists = big.NewInt(1)
		}, true},
		{"insert claims an old escrow key", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].OldEscrowKey = big.NewInt(1)
		}, true},
		{"insert into an occupied slot", func(c *UpdateMembersCircuit, w []spptest.MemberUpdateWitness) {
			c.Items[0].Index = w[1].Index
		}, true},
		{"insert into the sentinel slot", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].Index = 0
		}, true},
		{"insert with another successor", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].Next = big.NewInt(0x41)
		}, true},
		{"existing record misreports its lists", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[1].OldLists = big.NewInt(0)
		}, true},
		{"existing record at another index", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[1].Index = 2
		}, true},
		{"existing record claimed as an insert", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[1].Exists = 0
		}, true},
		{"insert claimed as existing", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].Exists = 1
		}, true},
		{"lists above 64 bits", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.Items[0].Lists = new(big.Int).Lsh(big.NewInt(1), 64)
		}, true},
		{"empty batch", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.ItemCount = 0
		}, true},
		{"oversized batch", func(c *UpdateMembersCircuit, _ []spptest.MemberUpdateWitness) {
			c.ItemCount = MaxBatch + 1
		}, true},
		{"index alias above the capacity", func(c *UpdateMembersCircuit, w []spptest.MemberUpdateWitness) {
			c.Items[0].Index = new(big.Int).Add(new(big.Int).SetUint64(w[0].Index), new(big.Int).Lsh(big.NewInt(1), Height))
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members, items := seed()
			c, witnesses := batchAssignment(t, members, items)
			tt.tamper(c, witnesses)
			if tt.rebind {
				bindBatch(t, c)
			}
			if solveBatch(t, c) == nil {
				t.Fatal("tampered batch solved")
			}
		})
	}
}

// A disabled item may carry any wires, only the first ItemCount items act.
func TestUpdateMembersIgnoresDisabledItems(t *testing.T) {
	members := spptest.NewMemberRegistry(t, Height)
	c, _ := batchAssignment(t, members, []hostItem{{big.NewInt(0x10), big.NewInt(1), big.NewInt(0)}})
	c.Items[1] = c.Items[0]
	c.Items[1].Member = big.NewInt(0x11)
	if err := solveBatch(t, c); err != nil {
		t.Fatal(err)
	}
}
