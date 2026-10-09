package emfield

import (
	"github.com/consensys/gnark/frontend"
)

// RangeCheck stands for a lookup range check of V to Bits bits. It exists only
// for Lean extraction: the lookup argument is committed in a deferred
// callback, so Lean receives it as the opaque predicate RangeCheck whose
// soundness is an explicit assumption.
type RangeCheck struct {
	V    frontend.Variable
	Bits int
}

func (RangeCheck) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (RangeCheck) OpaqueOutputs() int { return 0 }
