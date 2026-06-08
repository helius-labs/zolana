package transaction

import (
	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/circuit/gadget"

	"github.com/consensys/gnark/frontend"
)

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
	expiryUnixTs frontend.Variable,
) frontend.Variable {
	inputChain := gadget.HashChain(api, inputUtxoHashes)
	outputChain := gadget.HashChain(api, outputUtxoHashes)
	return poseidon.HashCircuitWithT(api, 5, []frontend.Variable{
		inputChain,
		outputChain,
		externalDataHash,
		expiryUnixTs,
	})
}
