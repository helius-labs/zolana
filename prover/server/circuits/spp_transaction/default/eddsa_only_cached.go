package defaultring

import (
	"fmt"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// CacheCapacity is the largest input count a cache can select from:
// the widest supported shape's input count, which is also how many commitments
// the cache account holds. It must equal CACHE_CAPACITY in
// program-libs/interface/src/state/cache.rs.
const CacheCapacity = 36

// CachedInputs binds selected cached UTXOs to transaction inputs.
// Bit i selects cache slot i for input i. InputHashChain is HashChain4 over
// NInputs commitments in slot order, with every unselected slot replaced by 0.
// The program must reconstruct these fields from a program-owned cache;
// the circuit proves commitment contents, not the cache's existence.
type CachedInputs struct {
	InputBitmap    frontend.Variable
	TreeID         frontend.Variable
	InputHashChain frontend.Variable
}

// DefaultRingEddsaOnlyCachedCircuit allows selected real inputs to spend from
// one cache. It needs its own verifying key and program-side cache checks.
// Its public hash appends [input bitmap, cache tree ID, input hash chain] to
// the default EdDSA circuit's preimage, after the output owner hash chain.
type DefaultRingEddsaOnlyCachedCircuit struct {
	DefaultRingEddsaOnlyCircuit
	CachedInputs CachedInputs
}

func NewDefaultRingEddsaOnlyCachedCircuit(shape shared.Shape) (*DefaultRingEddsaOnlyCachedCircuit, error) {
	if err := validateCachedShape(shape); err != nil {
		return nil, err
	}
	base, err := NewDefaultRingEddsaOnlyCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &DefaultRingEddsaOnlyCachedCircuit{DefaultRingEddsaOnlyCircuit: *base}, nil
}

func validateCachedShape(shape shared.Shape) error {
	if err := shape.Validate(); err != nil {
		return err
	}
	if shape.NInputs > CacheCapacity {
		return fmt.Errorf("spp: cached UTXO proving supports at most %d inputs, got %d", CacheCapacity, shape.NInputs)
	}
	return nil
}

func (c *DefaultRingEddsaOnlyCachedCircuit) Define(api frontend.API) error {
	if err := validateCachedShape(c.Shape); err != nil {
		return err
	}
	// ToBinary over the exact input count both decomposes the bitmap and
	// range-checks it, so no bit above the layout can select anything.
	selected := api.ToBinary(c.CachedInputs.InputBitmap, c.Shape.NInputs)
	api.AssertIsDifferent(c.CachedInputs.InputBitmap, 0)
	// Range-check alone: the tree id is a raw u16 everywhere else it appears.
	api.ToBinary(c.CachedInputs.TreeID, 16)

	inclusion := &shared.InclusionRelay{Skip: selected}
	tx := c.newTransaction(api)
	tx.Inclusion = inclusion
	tx.PreimageTail = append(
		append([]frontend.Variable{}, tx.PreimageTail...),
		c.CachedInputs.InputBitmap,
		c.CachedInputs.TreeID,
		c.CachedInputs.InputHashChain,
	)
	if err := c.define(api, tx); err != nil {
		return err
	}
	c.constrainCache(api, selected, inclusion)
	return nil
}

// constrainCache takes over what the state tree no longer proves: every
// selected input must be a real UTXO of the cache's own tree, and the
// selected commitments must chain to the value the program reconstructs.
func (c *DefaultRingEddsaOnlyCachedCircuit) constrainCache(
	api frontend.API,
	selected []frontend.Variable,
	inclusion *shared.InclusionRelay,
) {
	commitments := make([]frontend.Variable, c.Shape.NInputs)
	for i, isSelected := range selected {
		// Only a spendable UTXO can be drawn from a cache: a dummy slot
		// carries nothing and an address slot is created, not spent.
		isUtxo := api.IsZero(api.Sub(c.Private.Inputs[i].Utxo.Domain, shared.UtxoDomain))
		shared.AssertWhen(api, isSelected, isUtxo)
		// One cache belongs to one tree, and a commitment is hashed under its
		// tree, so a selected input must spend from that same tree.
		shared.AssertWhen(api, isSelected, api.IsZero(api.Sub(inclusion.TreeIDs[i], c.CachedInputs.TreeID)))
		// Zero denotes an empty cache slot and must never be spendable, or a
		// selected slot would be indistinguishable from a masked one.
		shared.AssertWhen(api, isSelected, api.Sub(1, api.IsZero(inclusion.Hashes[i])))
		commitments[i] = api.Mul(isSelected, inclusion.Hashes[i])
	}
	api.AssertIsEqual(gadget.HashChain4(api, commitments), c.CachedInputs.InputHashChain)
}
