package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// checkSources returns which slots serve their list, an empty slot carries a zero owner.
func (c *CustomRingPolicyCircuit) checkSources(api frontend.API) [NSources]frontend.Variable {
	var configured [NSources]frontend.Variable
	for i, source := range c.Sources {
		empty := api.IsZero(source.ListId)
		configured[i] = api.IsZero(api.Sub(source.ListId, i+1))
		api.AssertIsEqual(api.Add(empty, configured[i]), 1)
		api.AssertIsEqual(api.IsZero(source.OwnerHash), empty)
	}
	return configured
}

// sourceOwner is the namespace owner of an enabled fact's list, exactly one source serves it.
func (c *CustomRingPolicyCircuit) sourceOwner(api frontend.API, fact ListFactWires) frontend.Variable {
	matches, owner := frontend.Variable(0), frontend.Variable(0)
	for _, source := range c.Sources {
		selected := api.IsZero(api.Sub(fact.ListId, source.ListId))
		matches = api.Add(matches, selected)
		owner = api.Add(owner, api.Mul(selected, source.OwnerHash))
	}
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: fact.Enabled, A: matches, B: 1})
	return owner
}
