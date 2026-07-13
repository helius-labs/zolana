package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// HashChainGadget folds Poseidon over the inputs: h = inputs[0], then
// h = Poseidon(h, inputs[i]). Wrapped as an abstractor gadget so Lean
// extraction names one def per chain length; abstractor.Call is a passthrough
// on a real builder, so the R1CS is unchanged.
type HashChainGadget struct {
	Inputs []frontend.Variable
}

func (g HashChainGadget) DefineGadget(api frontend.API) interface{} {
	h := g.Inputs[0]
	for i := 1; i < len(g.Inputs); i++ {
		h = PoseidonHash(api, []frontend.Variable{h, g.Inputs[i]})
	}
	return h
}

func HashChain(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	return abstractor.Call(api, HashChainGadget{Inputs: inputs})
}
