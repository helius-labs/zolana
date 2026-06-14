package gadget

import (
	"github.com/consensys/gnark/frontend"
)

func HashChain(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	h := inputs[0]
	for i := 1; i < len(inputs); i++ {
		h = PoseidonHash(api, []frontend.Variable{h, inputs[i]})
	}
	return h
}
