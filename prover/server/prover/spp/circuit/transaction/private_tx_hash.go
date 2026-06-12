package transaction

import (
	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/circuit/gadget"

	"github.com/consensys/gnark/frontend"
)

// PrivateTxHashCircuit mirrors protocol.PrivateTxHash. expiry_unix_ts is bound
// through external_data_hash, not as a separate input (spec: SPP Proof).
func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
) frontend.Variable {
	inputChain := gadget.HashChain(api, inputUtxoHashes)
	outputChain := gadget.HashChain(api, outputUtxoHashes)
	return poseidon.HashCircuit(api, []frontend.Variable{
		inputChain,
		outputChain,
		externalDataHash,
	})
}
