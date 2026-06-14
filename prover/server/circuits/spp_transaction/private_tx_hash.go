package transaction

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// PrivateTxHashGadget mirrors protocol.PrivateTxHash. expiry_unix_ts is bound
// through external_data_hash, not as a separate input (spec: SPP Proof).
type PrivateTxHashGadget struct {
	InputUtxoHashes  []frontend.Variable
	OutputUtxoHashes []frontend.Variable
	ExternalDataHash frontend.Variable
}

func (gadget PrivateTxHashGadget) DefineGadget(api frontend.API) interface{} {
	inputChain := gadgetlib.HashChain(api, gadget.InputUtxoHashes)
	outputChain := gadgetlib.HashChain(api, gadget.OutputUtxoHashes)
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		inputChain,
		outputChain,
		gadget.ExternalDataHash,
	})
}

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
) frontend.Variable {
	return abstractor.Call(api, PrivateTxHashGadget{
		InputUtxoHashes:  inputUtxoHashes,
		OutputUtxoHashes: outputUtxoHashes,
		ExternalDataHash: externalDataHash,
	})
}
