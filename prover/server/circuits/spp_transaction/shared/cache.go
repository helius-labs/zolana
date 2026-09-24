package shared

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

type CachedInputs struct {
	TreeID        frontend.Variable
	ReadHashChain frontend.Variable
	ReadHashes    []frontend.Variable
	IsCached      []frontend.Variable
	ReadIndex     []frontend.Variable
}

func NewCachedInputs(nInputs int) CachedInputs {
	return CachedInputs{
		ReadHashes: make([]frontend.Variable, nInputs),
		IsCached:   make([]frontend.Variable, nInputs),
		ReadIndex:  make([]frontend.Variable, nInputs),
	}
}

func (c CachedInputs) lengthChecks(nInputs int) []LengthCheck {
	return []LengthCheck{
		{"cache read hash", len(c.ReadHashes), nInputs},
		{"cache input flag", len(c.IsCached), nInputs},
		{"cache read index", len(c.ReadIndex), nInputs},
	}
}

func (c CachedInputs) prepare(api frontend.API, tx *Transaction) {
	for _, cached := range c.IsCached {
		api.AssertIsBoolean(cached)
	}
	tx.skipInclusion = c.IsCached
	api.ToBinary(c.TreeID, 16)
	tx.PreimageTail = append(tx.PreimageTail, c.TreeID, c.ReadHashChain)
}

func (c CachedInputs) constrain(
	api frontend.API,
	tx Transaction,
	inputHashes []frontend.Variable,
	inputTreeIDs []frontend.Variable,
) {
	for i, cached := range c.IsCached {
		isUtxo := api.IsZero(api.Sub(tx.Inputs[i].Utxo.Domain, UtxoDomain))
		AssertWhen(api, cached, isUtxo)
		AssertWhen(api, cached, api.IsZero(api.Sub(inputTreeIDs[i], c.TreeID)))
		AssertWhen(api, cached, api.Sub(1, api.IsZero(inputHashes[i])))
		read := selectReadHash(api, c.ReadIndex[i], c.ReadHashes)
		AssertWhen(api, cached, api.IsZero(api.Sub(inputHashes[i], read)))
	}
	api.AssertIsEqual(gadget.RightHashChain4(api, c.ReadHashes), c.ReadHashChain)
}

func selectReadHash(api frontend.API, index frontend.Variable, hashes []frontend.Variable) frontend.Variable {
	var hits frontend.Variable = 0
	var selected frontend.Variable = 0
	for k, hash := range hashes {
		hit := api.IsZero(api.Sub(index, k))
		hits = api.Add(hits, hit)
		selected = api.Add(selected, api.Mul(hit, hash))
	}
	api.AssertIsEqual(hits, 1)
	return selected
}
