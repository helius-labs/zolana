package gadget

import (
	"fmt"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

func MerkleRoot(
	api frontend.API,
	leaf frontend.Variable,
	pathElements []frontend.Variable,
	pathIndexBits []frontend.Variable,
) frontend.Variable {
	if len(pathElements) != len(pathIndexBits) {
		panic(fmt.Sprintf("spp.MerkleRoot: pathElements=%d pathIndexBits=%d", len(pathElements), len(pathIndexBits)))
	}

	h := leaf
	for i := 0; i < len(pathElements); i++ {
		left := api.Select(pathIndexBits[i], pathElements[i], h)
		right := api.Sub(api.Add(h, pathElements[i]), left)
		h = poseidon.HashCircuit(api, []frontend.Variable{left, right})
	}
	return h
}
