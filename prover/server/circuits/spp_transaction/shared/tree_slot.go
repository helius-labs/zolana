package shared

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// TreeSlot is one tree account inputs may be spent from: its raw u16 id and
// the UTXO and nullifier roots SPP resolved for it. The three values travel
// together because an input's private slot must select all of them at once,
// so a UTXO cannot be hashed under one tree and proven against another's
// roots. An unused slot is all zero.
type TreeSlot struct {
	ID            frontend.Variable
	UtxoRoot      frontend.Variable
	NullifierRoot frontend.Variable
}

// NewTreeSlots allocates the InputTrees public tree slots.
func NewTreeSlots() []TreeSlot {
	return make([]TreeSlot, InputTrees)
}

// Hash commits to the slot as Poseidon(id, utxo root, nullifier root).
func (s TreeSlot) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{s.ID, s.UtxoRoot, s.NullifierRoot})
}

// TreeSlotsHashChain folds every slot's Hash right to left into the single
// public-input-hash element that commits to the tree slots. Unused slots sit
// at the end and are all zero, so their suffix of the chain is a constant SPP
// precomputes: a transaction over one tree costs it one slot hash and one
// chain step.
func TreeSlotsHashChain(api frontend.API, slots []TreeSlot) frontend.Variable {
	hashes := make([]frontend.Variable, len(slots))
	for k, slot := range slots {
		hashes[k] = slot.Hash(api)
	}
	return gadget.RightHashChain(api, hashes)
}

// SelectTreeSlot returns slots[slot] for a private slot index. It asserts that
// exactly one slot matches and that the selected slot publishes both roots, so
// an input can neither prove under two trees nor under an unused slot.
func SelectTreeSlot(api frontend.API, slot frontend.Variable, slots []TreeSlot) TreeSlot {
	var hits frontend.Variable = 0
	selected := TreeSlot{ID: 0, UtxoRoot: 0, NullifierRoot: 0}
	for k, candidate := range slots {
		sel := api.IsZero(api.Sub(slot, k))
		hits = api.Add(hits, sel)
		selected.ID = api.Add(selected.ID, api.Mul(sel, candidate.ID))
		selected.UtxoRoot = api.Add(selected.UtxoRoot, api.Mul(sel, candidate.UtxoRoot))
		selected.NullifierRoot = api.Add(selected.NullifierRoot, api.Mul(sel, candidate.NullifierRoot))
	}
	api.AssertIsEqual(hits, 1)
	api.AssertIsDifferent(selected.UtxoRoot, 0)
	api.AssertIsDifferent(selected.NullifierRoot, 0)
	return selected
}
