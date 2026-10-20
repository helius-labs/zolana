package nonnative

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

var edScalarOrder = new(big.Int).Add(pow2(252), func() *big.Int {
	v, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return v
}())

// fromLimbs range-checks each limb before attaching the layout widths.
func fromLimbs(f *Field, limbs []frontend.Variable) *Element {
	for i, l := range limbs {
		f.rc.Check(l, f.widths[i])
	}
	return f.Bounded(limbs, f.widths)
}

func edLimbs(v *big.Int) [6]frontend.Variable {
	var out [6]frontend.Variable
	for i, l := range edProjectionLayout.decompose(v, 6) {
		out[i] = l
	}
	return out
}
