package shared

import (
	gadgetlib "github.com/helius-labs/zolana/prover/server/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type privateTxHashGadget struct {
	InputUtxoHashes   []frontend.Variable
	OutputUtxoHashes  []frontend.Variable
	AddressNullifiers []frontend.Variable
	Blinding          frontend.Variable
}

func (gadget privateTxHashGadget) DefineGadget(api frontend.API) interface{} {
	inputChain := gadgetlib.NonZeroHashChain(api, gadget.InputUtxoHashes)
	outputChain := gadgetlib.NonZeroHashChain(api, gadget.OutputUtxoHashes)
	addressChain := gadgetlib.NonZeroHashChain(api, gadget.AddressNullifiers)
	return PrivateTxHashFromChains(api, inputChain, outputChain, addressChain, gadget.Blinding)
}

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	addressNullifiers []frontend.Variable,
	blinding frontend.Variable,
) frontend.Variable {
	return abstractor.Call(api, privateTxHashGadget{
		InputUtxoHashes:   inputUtxoHashes,
		OutputUtxoHashes:  outputUtxoHashes,
		AddressNullifiers: addressNullifiers,
		Blinding:          blinding,
	})
}

// PrivateTxHashFromChains requires each chain to be the NonZeroHashChain of its slot list.
func PrivateTxHashFromChains(
	api frontend.API,
	inputChain,
	outputChain,
	addressChain,
	blinding frontend.Variable,
) frontend.Variable {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, addressChain, blinding})
}
