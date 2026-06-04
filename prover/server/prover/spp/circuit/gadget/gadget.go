package gadget

import (
	"fmt"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

func StatePathFold(
	api frontend.API,
	leaf frontend.Variable,
	siblings []frontend.Variable,
	directions []frontend.Variable,
) frontend.Variable {
	if len(siblings) != len(directions) {
		panic(fmt.Sprintf("spp.StatePathFold: siblings=%d directions=%d", len(siblings), len(directions)))
	}
	h := leaf
	for i := 0; i < len(siblings); i++ {
		api.AssertIsBoolean(directions[i])
		left := api.Select(directions[i], siblings[i], h)
		right := api.Select(directions[i], h, siblings[i])
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{left, right})
	}
	return h
}

func IndexedLeafHash(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{value, nextValue})
}

func HashChain(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	h := inputs[0]
	for i := 1; i < len(inputs); i++ {
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{h, inputs[i]})
	}
	return h
}
