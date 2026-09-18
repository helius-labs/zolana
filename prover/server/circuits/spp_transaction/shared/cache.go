package shared

import (
	"zolana/prover/circuits/gadget"

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
// A zero bitmap uses ordinary state inclusion; its chain hashes NInputs zeros.
// The program must reconstruct these fields from a program-owned cache;
// the circuit proves commitment contents, not the cache's existence.
type CachedInputs struct {
	InputBitmap    frontend.Variable
	TreeID         frontend.Variable
	InputHashChain frontend.Variable
}

// prepare binds the cache fields and allows an empty bitmap for ordinary spends.
func (c CachedInputs) prepare(api frontend.API, tx *Transaction) {
	tx.skipInclusion = api.ToBinary(c.InputBitmap, tx.Shape.NInputs)
	api.ToBinary(c.TreeID, 16)
	tx.PreimageTail = append(tx.PreimageTail, c.InputBitmap, c.TreeID, c.InputHashChain)
}

// constrain takes over what the state tree no longer proves: every selected
// input must be a real UTXO of the cache's own tree, and the selected
// commitments must chain to the value the program reconstructs. It reads the
// commitment the core spent and the raw u16 id of the tree it spent it from
// back out of Constrain, so it recomputes neither and cannot drift from what
// the rest of the transaction constrains.
func (c CachedInputs) constrain(
	api frontend.API,
	tx Transaction,
	inputHashes []frontend.Variable,
	inputTreeIDs []frontend.Variable,
) {
	commitments := make([]frontend.Variable, len(tx.Inputs))
	for i, isSelected := range tx.skipInclusion {
		// Only a spendable UTXO can be drawn from a cache: a dummy slot
		// carries nothing and an address slot is created, not spent.
		isUtxo := api.IsZero(api.Sub(tx.Inputs[i].Utxo.Domain, UtxoDomain))
		AssertWhen(api, isSelected, isUtxo)
		// One cache belongs to one tree, and a commitment is hashed under its
		// tree, so a selected input must spend from that same tree.
		AssertWhen(api, isSelected, api.IsZero(api.Sub(inputTreeIDs[i], c.TreeID)))
		// Zero denotes an empty cache slot and must never be spendable, or a
		// selected slot would be indistinguishable from a masked one.
		AssertWhen(api, isSelected, api.Sub(1, api.IsZero(inputHashes[i])))
		commitments[i] = api.Mul(isSelected, inputHashes[i])
	}
	api.AssertIsEqual(gadget.HashChain4(api, commitments), c.InputHashChain)
}
