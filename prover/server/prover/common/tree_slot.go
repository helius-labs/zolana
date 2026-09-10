package common

import (
	"fmt"
	"math/big"
)

// TreeSlotParams is one public tree slot of a transfer or merge request: the
// raw u16 id of a tree account inputs may be spent from and the UTXO and
// nullifier roots SPP resolves for it. An unused slot is all zero. Every value
// is pre-computed client-side; the prover only assigns it onto circuit signals.
type TreeSlotParams struct {
	ID            *big.Int
	UtxoRoot      *big.Int
	NullifierRoot *big.Int
}

// TreeSlotParamsJSON is the wire form of TreeSlotParams, one field-element hex
// string per value.
type TreeSlotParamsJSON struct {
	ID            string `json:"id"`
	UtxoRoot      string `json:"utxoRoot"`
	NullifierRoot string `json:"nullifierRoot"`
}

// TreeSlotsToJSON encodes every slot; a nil value encodes as zero.
func TreeSlotsToJSON(slots []TreeSlotParams) []TreeSlotParamsJSON {
	out := make([]TreeSlotParamsJSON, len(slots))
	for k, slot := range slots {
		out[k] = TreeSlotParamsJSON{
			ID:            FeHex(slot.ID),
			UtxoRoot:      FeHex(slot.UtxoRoot),
			NullifierRoot: FeHex(slot.NullifierRoot),
		}
	}
	return out
}

// TreeSlotsFromJSON decodes every slot; an empty string decodes as zero.
func TreeSlotsFromJSON(slots []TreeSlotParamsJSON) ([]TreeSlotParams, error) {
	out := make([]TreeSlotParams, len(slots))
	for k, slot := range slots {
		var err error
		if out[k].ID, err = FeFromHex(slot.ID); err != nil {
			return nil, fmt.Errorf("spp: tree slot %d id: %w", k, err)
		}
		if out[k].UtxoRoot, err = FeFromHex(slot.UtxoRoot); err != nil {
			return nil, fmt.Errorf("spp: tree slot %d utxo root: %w", k, err)
		}
		if out[k].NullifierRoot, err = FeFromHex(slot.NullifierRoot); err != nil {
			return nil, fmt.Errorf("spp: tree slot %d nullifier root: %w", k, err)
		}
	}
	return out, nil
}

// ValidateTreeSlots checks the request-level tree slot layout the circuit was
// compiled for: exactly inputTrees slots, every input's slot index in range,
// and both roots of every selected slot non-zero. The circuit asserts the same
// (SelectTreeSlot), so failing here turns an opaque proving error into a
// request error.
func ValidateTreeSlots(slots []TreeSlotParams, inputSlots []*big.Int, inputTrees int) error {
	if len(slots) != inputTrees {
		return fmt.Errorf("spp: tree slot count mismatch: got %d want %d", len(slots), inputTrees)
	}
	for i, slot := range inputSlots {
		if slot == nil || slot.Sign() < 0 || slot.Cmp(big.NewInt(int64(inputTrees))) >= 0 {
			return fmt.Errorf("spp: input %d tree slot %v out of range [0, %d)", i, slot, inputTrees)
		}
		selected := slots[slot.Int64()]
		if isZero(selected.UtxoRoot) || isZero(selected.NullifierRoot) {
			return fmt.Errorf("spp: input %d selects unused tree slot %d", i, slot.Int64())
		}
	}
	return nil
}

func isZero(v *big.Int) bool {
	return v == nil || v.Sign() == 0
}
