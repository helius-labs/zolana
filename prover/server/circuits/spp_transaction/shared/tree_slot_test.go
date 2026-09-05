package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// treeSlotPinCircuit selects one slot and publishes its fields and the slot
// chain, so the selection and chain gadgets are testable without a full
// transaction witness.
type treeSlotPinCircuit struct {
	Slots    []TreeSlot
	Slot     frontend.Variable
	Selected TreeSlot          `gnark:",public"`
	Chain    frontend.Variable `gnark:",public"`
}

func (c *treeSlotPinCircuit) Define(api frontend.API) error {
	selected := SelectTreeSlot(api, c.Slot, c.Slots)
	api.AssertIsEqual(selected.ID, c.Selected.ID)
	api.AssertIsEqual(selected.UtxoRoot, c.Selected.UtxoRoot)
	api.AssertIsEqual(selected.NullifierRoot, c.Selected.NullifierRoot)
	api.AssertIsEqual(TreeSlotsHashChain(api, c.Slots), c.Chain)
	return nil
}

func newTreeSlotPinCircuit() *treeSlotPinCircuit {
	return &treeSlotPinCircuit{Slots: NewTreeSlots()}
}

// pinTreeSlots fills the first `populated` slots with distinct values and
// leaves the rest all zero, as SPP publishes a transaction over fewer trees.
func pinTreeSlots(populated int) []TreeSlot {
	slots := NewTreeSlots()
	for k := range slots {
		if k < populated {
			slots[k] = TreeSlot{
				ID:            spptest.Fe(int64(10 + k)),
				UtxoRoot:      spptest.Fe(int64(100 + k)),
				NullifierRoot: spptest.Fe(int64(200 + k)),
			}
		} else {
			slots[k] = TreeSlot{ID: 0, UtxoRoot: 0, NullifierRoot: 0}
		}
	}
	return slots
}

func pinAssignment(t testing.TB, slots []TreeSlot, slot int) *treeSlotPinCircuit {
	t.Helper()
	return &treeSlotPinCircuit{
		Slots:    slots,
		Slot:     spptest.Fe(int64(slot)),
		Selected: slots[slot],
		Chain:    spptest.MustTreeSlotsHashChain(t, treeSlotsToProtocol(slots)),
	}
}

// The in-circuit chain equals the host's right chain over per-slot hashes, and
// selection returns every populated slot.
func TestTreeSlotChainAndSelectionMatchHost(t *testing.T) {
	assert := test.NewAssert(t)
	slots := pinTreeSlots(InputTrees)
	for slot := 0; slot < InputTrees; slot++ {
		assert.SolvingSucceeded(newTreeSlotPinCircuit(), pinAssignment(t, slots, slot), test.WithCurves(ecc.BN254))
	}
}

// An all-zero slot is unused: selecting it fails even though the slot index is
// in range, because both roots must be non-zero.
func TestSelectTreeSlotRejectsUnusedSlot(t *testing.T) {
	assert := test.NewAssert(t)
	slots := pinTreeSlots(1)
	assert.SolvingSucceeded(newTreeSlotPinCircuit(), pinAssignment(t, slots, 0), test.WithCurves(ecc.BN254))
	assert.SolvingFailed(newTreeSlotPinCircuit(), pinAssignment(t, slots, 1), test.WithCurves(ecc.BN254))
}

// A slot with one root zeroed is rejected regardless of which root it is.
func TestSelectTreeSlotRejectsZeroRoot(t *testing.T) {
	assert := test.NewAssert(t)
	for _, zeroField := range []string{"utxo_root", "nullifier_root"} {
		t.Run(zeroField, func(t *testing.T) {
			slots := pinTreeSlots(InputTrees)
			if zeroField == "utxo_root" {
				slots[2].UtxoRoot = 0
			} else {
				slots[2].NullifierRoot = 0
			}
			assert.SolvingFailed(newTreeSlotPinCircuit(), pinAssignment(t, slots, 2), test.WithCurves(ecc.BN254))
		})
	}
}

// A single-tree transaction hashes as Poseidon(slot 0 hash, zero suffix), the
// form SPP evaluates with the suffix precomputed.
func TestTreeSlotChainSingleTreeUsesZeroSuffix(t *testing.T) {
	slots := treeSlotsToProtocol(pinTreeSlots(1))
	chain := spptest.MustTreeSlotsHashChain(t, slots)
	slotHash, err := protocol.TreeSlotHash(slots[0])
	slotHash = spptest.MustHash(t, slotHash, err)
	suffix, err := protocol.ZeroTreeSlotsSuffix(InputTrees - 1)
	suffix = spptest.MustHash(t, suffix, err)
	want := spptest.MustPoseidon(t, 3, []*big.Int{slotHash, suffix})
	if chain.Cmp(want) != 0 {
		t.Fatalf("single-tree chain = %s, want Poseidon(slot hash, zero suffix) = %s", chain, want)
	}
}
