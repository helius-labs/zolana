package transaction

import (
	gadgetlib "light/light-prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// assertEqualWhen constrains a == b only when cond == 1 (see
// gadget.AssertEqualWhen). For cond == 0 the check is vacuously satisfied.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadgetlib.AssertEqualWhen{Cond: cond, A: a, B: b})
}

// assertZeroWhen constrains v == 0 only when cond == 1 (see gadget.AssertZeroWhen).
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadgetlib.AssertZeroWhen{Cond: cond, V: v})
}
