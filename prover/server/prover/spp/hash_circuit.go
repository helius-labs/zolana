package spp

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

type UtxoCircuitFields struct {
	Domain          frontend.Variable
	Owner           frontend.Variable
	AssetID         frontend.Variable
	AssetAmount     frontend.Variable
	Blinding        frontend.Variable
	DataHash        frontend.Variable
	PolicyData      frontend.Variable
	PolicyProgramID frontend.Variable
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 9, []frontend.Variable{
		u.Domain,
		u.Owner,
		u.AssetID,
		u.AssetAmount,
		u.Blinding,
		u.DataHash,
		u.PolicyData,
		u.PolicyProgramID,
	})
}

func PreNullifierCircuit(api frontend.API, blinding, nullifierSecret frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{
		blinding,
		nullifierSecret,
	})
}

func NullifierHashCircuit(
	api frontend.API,
	utxoHash frontend.Variable,
	preNullifier frontend.Variable,
) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{
		utxoHash,
		preNullifier,
	})
}

func HashChainCircuit(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	h := inputs[len(inputs)-1]
	for i := len(inputs) - 2; i >= 0; i-- {
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{inputs[i], h})
	}
	return h
}

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
	expiryUnixTs frontend.Variable,
) frontend.Variable {
	inputChain := HashChainCircuit(api, inputUtxoHashes)
	outputChain := HashChainCircuit(api, outputUtxoHashes)
	return poseidon.HashCircuitWithT(api, 5, []frontend.Variable{
		inputChain,
		outputChain,
		externalDataHash,
		expiryUnixTs,
	})
}
