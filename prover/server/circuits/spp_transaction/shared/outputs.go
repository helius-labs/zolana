package shared

import (
	"github.com/consensys/gnark/frontend"
)

// Returns array of all owner pubkeys of input UTXOs that signed.
func SignerOwners(api frontend.API, inputs []Input) Signers {
	owners := make(Signers, len(inputs))
	for i, in := range inputs {
		owners[i] = api.Mul(in.isUtxoOrAddress(api), in.Utxo.Owner)
	}
	return owners
}

func OutputOwners(outputs []UtxoCircuitFields) []frontend.Variable {
	owners := make([]frontend.Variable, len(outputs))
	for i, utxo := range outputs {
		owners[i] = utxo.Owner
	}
	return owners
}

func constrainOutput(api frontend.API, utxo UtxoCircuitFields, hash, ownerSigned frontend.Variable) frontend.Variable {
	isUtxo := utxo.isUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	// 1. All fields must be 0 except blinding.
	AssertWhen(api, utxo.isDummy(api), utxo.checkDummy(api))

	// 2. if utxo program data is set owner must have signed.
	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), ownerSigned)

	utxoHash := UtxoHashCircuit(api, utxo)
	api.AssertIsEqual(utxoHash, hash)

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
}
