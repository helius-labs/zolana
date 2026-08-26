package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// resolveOwner returns the records owner the map names for the entry's kind.
// An enabled entry must match exactly one slot, a disabled entry resolves to
// garbage no downstream assertion reads.
func resolveOwner(api frontend.API, sources [NSources]SourceWires, entry PoolEntryWires) frontend.Variable {
	sum := frontend.Variable(0)
	owner := frontend.Variable(0)
	for _, src := range sources {
		selected := api.IsZero(api.Sub(entry.Kind, src.Kind))
		sum = api.Add(sum, selected)
		owner = api.Add(owner, api.Mul(selected, src.OwnerHash))
	}
	// Gated on Enabled, a disabled padding entry may share a kind with a live
	// slot.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: entry.Enabled, A: sum, B: 1})
	return owner
}
