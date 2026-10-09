package emcurve

import (
	"github.com/consensys/gnark/frontend"
)

// RowLookup stands for a log-derivative row lookup of Rows[Index]. It exists
// only for Lean extraction, where the deferred lookup argument becomes the
// opaque predicate RowLookup_<columns>_<rows> with an explicit soundness
// assumption.
type RowLookup struct {
	Rows  [][]frontend.Variable
	Index frontend.Variable
}

func (RowLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (g RowLookup) OpaqueOutputs() int {
	if len(g.Rows) == 0 {
		panic("row lookup without rows")
	}
	return len(g.Rows[0])
}
