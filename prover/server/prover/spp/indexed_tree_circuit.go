package spp

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

// IndexedLeafHashCircuit hashes an indexed nullifier-tree leaf, Poseidon(value,
// nextValue). The off-circuit twin is IndexedLeafHash in indexed_tree.go.
func IndexedLeafHashCircuit(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{value, nextValue})
}
