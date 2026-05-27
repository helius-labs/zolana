package spp

import (
	"fmt"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

func StatePathFoldCircuit(
	api frontend.API,
	leaf frontend.Variable,
	siblings []frontend.Variable,
	directions []frontend.Variable,
) frontend.Variable {
	if len(siblings) != len(directions) {
		panic(fmt.Sprintf("spp.StatePathFoldCircuit: siblings=%d directions=%d", len(siblings), len(directions)))
	}
	h := leaf
	for j := 0; j < len(siblings); j++ {
		api.AssertIsBoolean(directions[j])
		left := api.Select(directions[j], siblings[j], h)
		right := api.Select(directions[j], h, siblings[j])
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{left, right})
	}
	return h
}

func IndexedLeafHashCircuit(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{value, nextValue})
}

func RootBindingCircuit(api frontend.API, stateRoot, nullifierRoot frontend.Variable) frontend.Variable {
	return HashChainCircuit(api, []frontend.Variable{stateRoot, nullifierRoot})
}
