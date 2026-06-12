package gadget

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

func IndexedLeafHash(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return poseidon.HashCircuit(api, []frontend.Variable{value, nextValue})
}
