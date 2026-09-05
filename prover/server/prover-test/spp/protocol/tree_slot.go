package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

// TreeSlot is one tree account inputs may be spent from: its raw u16 id and
// the UTXO and nullifier roots SPP resolved for it. An unused slot is all zero.
type TreeSlot struct {
	ID            *big.Int
	UtxoRoot      *big.Int
	NullifierRoot *big.Int
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
	zero := big.NewInt(0)
	slots := make([]TreeSlot, count)
	for k := range slots {
		slots[k] = TreeSlot{ID: zero, UtxoRoot: zero, NullifierRoot: zero}
	}
	return TreeSlotsHashChain(slots)
}
