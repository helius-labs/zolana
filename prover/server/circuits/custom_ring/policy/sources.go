package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// Source slot i is empty or serves list i+1.
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

func resolveSourceOwner(api frontend.API, sources [NSources]SourceWires, answer AnswerWires) frontend.Variable {
	matchCount := frontend.Variable(0)
	sourceOwnerHash := frontend.Variable(0)
	for _, source := range sources {
		selected := api.IsZero(api.Sub(answer.ListId, source.ListId))
		matchCount = api.Add(matchCount, selected)
		sourceOwnerHash = api.Add(sourceOwnerHash, api.Mul(selected, source.OwnerHash))
	}
	// Enabled answers resolve to exactly one source.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: answer.Enabled, A: matchCount, B: 1})
	return sourceOwnerHash
}
