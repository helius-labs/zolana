package shared

import (
	"github.com/consensys/gnark/frontend"
)

// SignerOwners projects the signer array onto the owner identities it proved:
// the owner hash of every input slot that carries content, which constrainInput
// bound to that slot's signer. Slots that carry nothing are masked to 0.
func SignerOwners(api frontend.API, inputs []Input) Signers {
	owners := make(Signers, len(inputs))
	for i, in := range inputs {
		owners[i] = api.Mul(in.isUtxoOrAddress(api), in.Utxo.Owner)
	}
	return owners
}

// OutputOwners lists the owner hash of every output slot — the identity a
// data-carrying output must have signed with on the variants that publish no
// output owner tag.
func OutputOwners(outputs []UtxoCircuitFields) []frontend.Variable {
	owners := make([]frontend.Variable, len(outputs))
	for i, utxo := range outputs {
		owners[i] = utxo.Owner
	}
	return owners
}

// constrainOutput classifies the slot, pins dummies, requires ownerSigned for
// data-carrying outputs, and binds the public hash to the utxo (dummies
// included — the public hash is the blinded dummy hash). Returns
// Select(isUtxo, utxoHash, 0) for the private-tx-hash chain.
func constrainOutput(api frontend.API, utxo UtxoCircuitFields, hash, ownerSigned frontend.Variable) frontend.Variable {
	isUtxo := utxo.isUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	// Same asset-0 rule as the input side: a real output must name a real asset.
	assertZeroWhen(api, isUtxo, api.IsZero(utxo.Asset))

	assertWhen(api, utxo.isDummy(api), utxo.checkDummy(api))

	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	assertWhen(api, api.Mul(isUtxo, dataIsSet), ownerSigned)

	utxoHash := UtxoHashCircuit(api, utxo)
	api.AssertIsEqual(utxoHash, hash)

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
}
