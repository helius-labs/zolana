package shared

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type privateTxHashGadget struct {
	InputUtxoHashes   []frontend.Variable
	OutputUtxoHashes  []frontend.Variable
	AddressUtxoHashes []frontend.Variable
	ExternalDataHash  frontend.Variable
	Blinding          frontend.Variable
}

func (gadget privateTxHashGadget) DefineGadget(api frontend.API) interface{} {
	inputChain := gadgetlib.HashChain(api, gadget.InputUtxoHashes)
	outputChain := gadgetlib.HashChain(api, gadget.OutputUtxoHashes)
	addressChain := gadgetlib.HashChain(api, gadget.AddressUtxoHashes)
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
	addressUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
	blinding frontend.Variable,
) frontend.Variable {
	api.AssertIsDifferent(blinding, 0)
	return abstractor.Call(api, privateTxHashGadget{
		InputUtxoHashes:   inputUtxoHashes,
		OutputUtxoHashes:  outputUtxoHashes,
		AddressUtxoHashes: addressUtxoHashes,
		ExternalDataHash:  externalDataHash,
		Blinding:          blinding,
	})
}
