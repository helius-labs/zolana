package defaultring

import (
	"fmt"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// ProveByIndexCapacity is the largest input count a receipt can select from,
// bounding the bitmap to bits the field holds with room to spare.
const ProveByIndexCapacity = 36

// ProveByIndex binds one receipt's selected slots to transaction inputs.
// Bit i selects receipt slot i for input i. InputHashChain is HashChain4 over
// NInputs commitments in slot order, with every unselected slot replaced by 0.
// The program must reconstruct these fields from a program-owned receipt;
// the circuit proves commitment contents, not the receipt's existence.
type ProveByIndex struct {
	InputBitmap    frontend.Variable
	TreeID         frontend.Variable
	InputHashChain frontend.Variable
}

// DefaultRingEddsaOnlyByIndexCircuit allows selected real inputs to spend from
// one receipt. It needs its own verifying key and program-side receipt checks.
// Its public hash appends [input bitmap, receipt tree ID, input hash chain] to
// the default EdDSA circuit's preimage, after the output owner hash chain.
type DefaultRingEddsaOnlyByIndexCircuit struct {
	DefaultRingEddsaOnlyCircuit
	ProveByIndex ProveByIndex
}

func NewDefaultRingEddsaOnlyByIndexCircuit(shape shared.Shape) (*DefaultRingEddsaOnlyByIndexCircuit, error) {
	if err := validateByIndexShape(shape); err != nil {
		return nil, err
	}
	base, err := NewDefaultRingEddsaOnlyCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &DefaultRingEddsaOnlyByIndexCircuit{DefaultRingEddsaOnlyCircuit: *base}, nil
}

func validateByIndexShape(shape shared.Shape) error {
	if err := shape.Validate(); err != nil {
		return err
	}
	if shape.NInputs > ProveByIndexCapacity {
		return fmt.Errorf("spp: prove-by-index supports at most %d inputs, got %d", ProveByIndexCapacity, shape.NInputs)
	}
	return nil
}

func (c *DefaultRingEddsaOnlyByIndexCircuit) Define(api frontend.API) error {
	if err := validateByIndexShape(c.Shape); err != nil {
		return err
	}
	// ToBinary over the exact input count both decomposes the bitmap and
	// range-checks it, so no bit above the layout can select anything.
	selected := api.ToBinary(c.ProveByIndex.InputBitmap, c.Shape.NInputs)
	api.AssertIsDifferent(c.ProveByIndex.InputBitmap, 0)
	api.ToBinary(c.ProveByIndex.TreeID, 16)

	inclusion := &shared.InclusionRelay{Skip: selected}
	tx := c.newTransaction(api)
	tx.Inclusion = inclusion
	tx.PreimageTail = append(
		append([]frontend.Variable{}, tx.PreimageTail...),
		c.ProveByIndex.InputBitmap,
		c.ProveByIndex.TreeID,
		c.ProveByIndex.InputHashChain,
	)
	if err := c.define(api, tx); err != nil {
		return err
	}
	return c.constrainReceipt(api, selected, inclusion)
}

// constrainReceipt takes over what the state tree no longer proves: every
// selected input must be a real UTXO of the receipt's own tree, and the
// selected commitments must chain to the value the program reconstructs.
func (c *DefaultRingEddsaOnlyByIndexCircuit) constrainReceipt(
	api frontend.API,
	selected []frontend.Variable,
	inclusion *shared.InclusionRelay,
) error {
	if err := shared.ValidateLength("receipt commitment", len(inclusion.Hashes), c.Shape.NInputs); err != nil {
		return err
	}
	commitments := make([]frontend.Variable, c.Shape.NInputs)
	for i, isSelected := range selected {
		// Only a spendable UTXO can be drawn from a receipt: a dummy slot
		// carries nothing and an address slot is created, not spent.
		isUtxo := api.IsZero(api.Sub(c.Private.Inputs[i].Utxo.Domain, shared.UtxoDomain))
		shared.AssertWhen(api, isSelected, isUtxo)
		// One receipt belongs to one tree, and a commitment is hashed under its
		// tree, so a selected input must spend from that same tree.
		shared.AssertWhen(api, isSelected, api.IsZero(api.Sub(inclusion.TreeIDs[i], c.ProveByIndex.TreeID)))
		// Zero denotes an empty receipt slot and must never be spendable, or a
		// selected slot would be indistinguishable from a masked one.
		shared.AssertWhen(api, isSelected, api.Sub(1, api.IsZero(inclusion.Hashes[i])))
		commitments[i] = api.Mul(isSelected, inclusion.Hashes[i])
	}
	api.AssertIsEqual(gadget.HashChain4(api, commitments), c.ProveByIndex.InputHashChain)
	return nil
}
