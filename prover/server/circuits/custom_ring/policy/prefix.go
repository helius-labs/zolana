package policy

import (
	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
)

// oneHot[0] selects the first contribution.
func hashPrefix(api frontend.API, contributions, oneHot []frontend.Variable) frontend.Variable {
	return extendHashPrefix(api, contributions[0], contributions[1:], oneHot)
}

// oneHot[0] selects the unchanged head.
func extendHashPrefix(api frontend.API, head frontend.Variable, values, oneHot []frontend.Variable) frontend.Variable {
	chain := head
	selected := api.Mul(oneHot[0], chain)
	for k, value := range values {
		chain = gadget.PoseidonHash(api, []frontend.Variable{chain, value})
		selected = api.Add(selected, api.Mul(oneHot[k+1], chain))
	}
	return selected
}

func assertOneHot(api frontend.API, oneHot []frontend.Variable) {
	sum := frontend.Variable(0)
	for _, bit := range oneHot {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, bit)
	}
	api.AssertIsEqual(sum, 1)
}

// Each position sums the selected count and all larger counts.
func suffixSums(api frontend.API, oneHot []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(oneHot))
	sum := frontend.Variable(0)
	for k := len(oneHot) - 1; k >= 0; k-- {
		sum = api.Add(sum, oneHot[k])
		out[k] = sum
	}
	return out
}
