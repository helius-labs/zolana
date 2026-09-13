package shared

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// privateTxHashGadget folds the three per-slot chains, each a HashChain4,
// with the external data hash and the private blinding. AddressNullifiers holds one entry per input
// slot: the nullifier (compressed address) of every address slot, 0 elsewhere.
type privateTxHashGadget struct {
	InputUtxoHashes   []frontend.Variable
	OutputUtxoHashes  []frontend.Variable
	AddressNullifiers []frontend.Variable
	ExternalDataHash  frontend.Variable
	Blinding          frontend.Variable
}

func (gadget privateTxHashGadget) DefineGadget(api frontend.API) interface{} {
	inputChain := gadgetlib.HashChain4(api, gadget.InputUtxoHashes)
	outputChain := gadgetlib.HashChain4(api, gadget.OutputUtxoHashes)
	addressChain := gadgetlib.HashChain4(api, gadget.AddressNullifiers)
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		inputChain,
		outputChain,
		addressChain,
		gadget.ExternalDataHash,
		gadget.Blinding,
	})
}

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	addressNullifiers []frontend.Variable,
	externalDataHash frontend.Variable,
	blinding frontend.Variable,
) frontend.Variable {
	return abstractor.Call(api, privateTxHashGadget{
		InputUtxoHashes:   inputUtxoHashes,
		OutputUtxoHashes:  outputUtxoHashes,
		AddressNullifiers: addressNullifiers,
		ExternalDataHash:  externalDataHash,
		Blinding:          blinding,
	})
}
