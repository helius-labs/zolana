package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// An enabled entry must match exactly one slot, a disabled entry resolves to
// garbage no downstream assertion reads.
func resolveOwner(api frontend.API, sources [NSources]SourceWires, entry RuleAnswerWires) frontend.Variable {
	sum := frontend.Variable(0)
	owner := frontend.Variable(0)
	for _, src := range sources {
		selected := api.IsZero(api.Sub(entry.ListId, src.ListId))
		sum = api.Add(sum, selected)
		owner = api.Add(owner, api.Mul(selected, src.OwnerHash))
	}
	// Gated on Enabled, a disabled padding entry may share a listId with a live
	// slot.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: entry.Enabled, A: sum, B: 1})
	return owner
}
