package shared

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// OutputBlindingDomainV1 is the 32-bit ASCII tag "TXOB". It must match
// DOMAIN_TRANSACT_OUTPUT_BLINDING_V1 in sdk-libs/transaction/src/utxo.rs.
const OutputBlindingDomainV1 = 0x54584f42

// DeriveOutputBlinding binds one output's blinding to the transaction's first
// single-use nullifier, one private transaction seed, and the physical output
// slot. The slot is the final zero-based position after padding.
func DeriveOutputBlinding(
	api frontend.API,
	firstNullifier,
	seed frontend.Variable,
	outputIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		OutputBlindingDomainV1,
		firstNullifier,
		seed,
		outputIndex,
	})
}

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

// ConstrainOutput validates and hash-binds one transaction output.
func ConstrainOutput(api frontend.API, utxo UtxoCircuitFields, hash, ownerSigned frontend.Variable) frontend.Variable {
	isUtxo := utxo.isUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	// Same asset-0 rule as the input side: a real output must name a real asset.
	assertZeroWhen(api, isUtxo, api.IsZero(utxo.Asset))

	// 1. All fields must be 0 except blinding.
	AssertWhen(api, utxo.isDummy(api), utxo.CheckDummy(api))

	// 2. if utxo program data is set owner must have signed.
	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), ownerSigned)

	utxoHash := UtxoHashCircuit(api, utxo)
	api.AssertIsEqual(utxoHash, hash)

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
}
