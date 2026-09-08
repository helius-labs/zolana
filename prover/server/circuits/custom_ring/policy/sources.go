// Checks the owner configured for each list and requires one source per
// enabled fact to derive its entry address.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// checkSources fixes one namespace owner per list and identifies configured
// slots.
func (c *CustomRingPolicyCircuit) checkSources(api frontend.API) [NSources]frontend.Variable {
	var configured [NSources]frontend.Variable
	for i, source := range c.Sources {
		// 1. Restrict each slot to empty or its positional list ID.
		empty := api.IsZero(source.ListId)
		configured[i] = api.IsZero(api.Sub(source.ListId, i+1))
		api.AssertIsEqual(api.Add(empty, configured[i]), 1)

		// 2. Require a nonzero namespace owner only for configured
		// slots.
		api.AssertIsEqual(api.IsZero(source.OwnerHash), empty)
	}
	return configured
}

// resolveSourceOwner selects the namespace owner that determines the entry
// address.
func resolveSourceOwner(api frontend.API, sources [NSources]SourceWires, fact ListFactWires) frontend.Variable {
	// 1. Select the owner for the claimed list.
	matchCount := frontend.Variable(0)
	sourceOwnerHash := frontend.Variable(0)
	for _, source := range sources {
		selected := api.IsZero(api.Sub(fact.ListId, source.ListId))
		matchCount = api.Add(matchCount, selected)
		sourceOwnerHash = api.Add(sourceOwnerHash, api.Mul(selected, source.OwnerHash))
	}

	// 2. Require exactly one source for each enabled list fact.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: fact.Enabled, A: matchCount, B: 1})
	return sourceOwnerHash
}
