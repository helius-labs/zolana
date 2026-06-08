package gadget

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

func IndexedLeafHash(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{value, nextValue})
}
