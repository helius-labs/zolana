package gadget

import (
	"github.com/consensys/gnark/frontend"
)

// AssertEqualWhen constrains a == b only when cond == 1. For cond == 0 the
// product is 0 regardless, so the check is vacuously satisfied (skipped).
type AssertEqualWhen struct {
	Cond frontend.Variable
	A    frontend.Variable
	B    frontend.Variable
}

func (gadget AssertEqualWhen) DefineGadget(api frontend.API) interface{} {
	api.AssertIsEqual(api.Mul(gadget.Cond, api.Sub(gadget.A, gadget.B)), 0)
	return []frontend.Variable{}
}

// AssertZeroWhen constrains v == 0 only when cond == 1.
type AssertZeroWhen struct {
	Cond frontend.Variable
	V    frontend.Variable
}

func (gadget AssertZeroWhen) DefineGadget(api frontend.API) interface{} {
	api.AssertIsEqual(api.Mul(gadget.Cond, gadget.V), 0)
	return []frontend.Variable{}
}
