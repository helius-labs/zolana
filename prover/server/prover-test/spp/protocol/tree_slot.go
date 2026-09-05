package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

// InputTrees is the number of tree slots a proof spends from. It mirrors the
// circuit constant of the same name (circuits/spp_transaction/shared), which
// this package cannot import.
const InputTrees = 5

// TreeSlot is one tree account inputs may be spent from: its raw u16 id and
// the UTXO and nullifier roots SPP resolved for it. An unused slot is all zero.
type TreeSlot struct {
	ID            *big.Int
	UtxoRoot      *big.Int
	NullifierRoot *big.Int
}

// ZeroTreeSlot is an unused slot. The circuit rejects selecting it because both
// roots are zero, so only populated slots can be spent from.
func ZeroTreeSlot() TreeSlot {
	return TreeSlot{ID: big.NewInt(0), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(0)}
}

// PadTreeSlots places the given slots first and fills the remaining InputTrees
// positions with all-zero slots, the layout SPP publishes when a transaction
// spends from fewer than InputTrees trees.
func PadTreeSlots(slots ...TreeSlot) ([]TreeSlot, error) {
	if len(slots) > InputTrees {
		return nil, fmt.Errorf("spp: %d tree slots exceed the %d input trees", len(slots), InputTrees)
	}
	out := make([]TreeSlot, InputTrees)
	copy(out, slots)
	for k := len(slots); k < InputTrees; k++ {
		out[k] = ZeroTreeSlot()
	}
	return out, nil
}

// TreeSlotHash commits to one slot as Poseidon(id, utxo root, nullifier root).
func TreeSlotHash(slot TreeSlot) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{slot.ID, slot.UtxoRoot, slot.NullifierRoot})
	if err != nil {
		return nil, fmt.Errorf("spp: tree slot hash: %w", err)
	}
	return h, nil
}

// TreeSlotsHashChain folds every slot's TreeSlotHash right to left into the
// public-input-hash element that commits to the tree slots, mirroring the
// circuit's TreeSlotsHashChain. Unused slots are all zero and sit at the end,
// so SPP precomputes their suffix (ZeroTreeSlotsSuffix).
func TreeSlotsHashChain(slots []TreeSlot) (*big.Int, error) {
	hashes := make([]*big.Int, len(slots))
	for k, slot := range slots {
		h, err := TreeSlotHash(slot)
		if err != nil {
			return nil, fmt.Errorf("spp: tree slot %d: %w", k, err)
		}
		hashes[k] = h
	}
	return RightHashChain(hashes)
}

// ZeroTreeSlotsSuffix is the right hash chain over count all-zero slots: the
// constant SPP starts from when only the first InputTrees-count slots are
// populated.
func ZeroTreeSlotsSuffix(count int) (*big.Int, error) {
	slots := make([]TreeSlot, count)
	for k := range slots {
		slots[k] = ZeroTreeSlot()
	}
	return TreeSlotsHashChain(slots)
}
