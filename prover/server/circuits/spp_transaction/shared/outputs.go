package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	gadgetlib "zolana/prover/circuits/gadget"
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

// ConstrainOutput validates and hash-binds one transaction output.
//
// isCompact must be IsZero(hash) (CompactSlots), or 0 for an output that is
// always real.
func ConstrainOutput(api frontend.API, utxo UtxoCircuitFields, hash, isCompact, ownerSigned, treeID frontend.Variable) frontend.Variable {
	isUtxo := utxo.isUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	// Same asset-0 rule as the input side: a real output must name a real asset.
	assertZeroWhen(api, isUtxo, api.IsZero(utxo.Asset))

	// 1. All fields must be 0 except blinding.
	AssertWhen(api, utxo.isDummy(api), utxo.CheckDummy(api))

	// 2. if utxo program data is set owner must have signed.
	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), ownerSigned)

	// 3. A zero public hash marks compact padding: the slot must be a dummy,
	// and SPP neither receives nor appends it.
	AssertWhen(api, isCompact, utxo.isDummy(api))
	utxoHash := UtxoHashCircuit(api, utxo, treeID)
	abstractor.CallVoid(api, gadgetlib.AssertEqualWhen{Cond: api.Sub(1, isCompact), A: utxoHash, B: hash})

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
}
