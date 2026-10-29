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
	return PrivateTxHashChains{
		InputChain:   gadgetlib.NonZeroHashChain(api, gadget.InputUtxoHashes),
		OutputChain:  gadgetlib.NonZeroHashChain(api, gadget.OutputUtxoHashes),
		AddressChain: gadgetlib.NonZeroHashChain(api, gadget.AddressNullifiers),
		Blinding:     gadget.Blinding,
	}.Hash(api)
}

type PrivateTxHashChains struct {
	InputChain   frontend.Variable
	OutputChain  frontend.Variable
	AddressChain frontend.Variable
	Blinding     frontend.Variable
}

// Hash is SPP's private_tx_hash only when each chain is the NonZeroHashChain of its slot list.
func (chains PrivateTxHashChains) Hash(api frontend.API) frontend.Variable {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{chains.InputChain, chains.OutputChain, chains.AddressChain, chains.Blinding})
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
