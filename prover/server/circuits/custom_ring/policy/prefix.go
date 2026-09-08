package policy

import (
	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
)

// hashPrefix binds a nonempty prefix of transaction contributions.
// oneHot[0] selects the first contribution.
func hashPrefix(api frontend.API, contributions, oneHot []frontend.Variable) frontend.Variable {
	return extendHashPrefix(api, contributions[0], contributions[1:], oneHot)
}

// extendHashPrefix adds only the selected prefix to a committed head.
// oneHot[0] selects the unchanged head.
func extendHashPrefix(api frontend.API, head frontend.Variable, values, oneHot []frontend.Variable) frontend.Variable {
	// 1. Select the unchanged head for an empty extension.
	chain := head
	selected := api.Mul(oneHot[0], chain)

	// 2. Hash each extension and select the committed prefix.
	for k, value := range values {
		chain = gadget.PoseidonHash(api, []frontend.Variable{chain, value})
		selected = api.Add(selected, api.Mul(oneHot[k+1], chain))
	}
	return selected
}

// assertOneHot forces one count choice before prefix hashing and slot
// selection.
func assertOneHot(api frontend.API, oneHot []frontend.Variable) {
	// 1. Restrict each count selector to a bit.
	sum := frontend.Variable(0)
	for _, bit := range oneHot {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, bit)
	}

	// 2. Require exactly one selected count.
	api.AssertIsEqual(sum, 1)
}

// suffixSums derives prefix flags for hashing and evaluation from a checked
// one-hot count.
// Position k is set when the selected index is at least k.
func suffixSums(api frontend.API, oneHot []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(oneHot))
	sum := frontend.Variable(0)
	for k := len(oneHot) - 1; k >= 0; k-- {
		sum = api.Add(sum, oneHot[k])
		out[k] = sum
	}
	return out
}
