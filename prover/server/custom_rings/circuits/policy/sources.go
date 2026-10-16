package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// sourcesView is the configured lists and which of them a curator registry serves.
type sourcesView struct {
	// configured[i] is set when slot i serves list i+1.
	configured [NSources]frontend.Variable
	// foreign[i] is set when list i+1 is read from the curator registry.
	foreign [NSources]frontend.Variable
	// anyForeign is set when a curator registry is configured at all.
	anyForeign frontend.Variable
}

// checkSources admits empty slots and positional slots, every curator slot names the one foreign registry.
func (c *CustomRingPolicyCircuit) checkSources(api frontend.API) sourcesView {
	var view sourcesView
	view.anyForeign = frontend.Variable(0)
	curator := frontend.Variable(0)
	for i, source := range c.Sources {
		empty := api.IsZero(source.ListId)
		view.configured[i] = api.IsZero(api.Sub(source.ListId, i+1))
		api.AssertIsEqual(api.Add(empty, view.configured[i]), 1)
		api.AssertIsEqual(api.Mul(empty, source.Registry), 0)
		view.foreign[i] = base.NonZero(api, source.Registry)
		view.anyForeign = api.Or(view.anyForeign, view.foreign[i])
		curator = api.Select(view.foreign[i], source.Registry, curator)
	}
	for i, source := range c.Sources {
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: view.foreign[i], A: source.Registry, B: curator})
	}
	// Without a curator the program binds a zero foreign root.
	api.AssertIsEqual(api.Mul(api.Sub(1, view.anyForeign), c.ForeignRoot), 0)
	return view
}
