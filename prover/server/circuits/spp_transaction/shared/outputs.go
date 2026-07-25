package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SignerOwners collects the owner hash of every real input slot — the
// identities checkOwnership binds to a verified signer. Non-real slots are
// masked to zero, which checkOwnerSigned never matches.
func SignerOwners(api frontend.API, inputs []Input) []frontend.Variable {
	signers := make([]frontend.Variable, len(inputs))
	for i, in := range inputs {
		signers[i] = api.Mul(in.isUtxoOrAddress(api), in.Utxo.Owner)
	}
	return signers
}

// ConstrainDefaultZoneOutput — default zone: an output must not be a member
// of a zone, and a real output's owner_hash must recompute from the public
// owner tag (ownerPkHash) and the witnessed nullifierPk. Dummy slots skip the
// owner binding so their public tag stays free.
func ConstrainDefaultZoneOutput(
	api frontend.API,
	utxo UtxoCircuitFields,
	hash, ownerPkHash, nullifierPk frontend.Variable,
	signers []frontend.Variable,
) frontend.Variable {
	utxo.AssertInDefaultZone(api)
	AssertWhen(api, utxo.IsUtxo(api), checkOwnerIsPublicInput(api, utxo, ownerPkHash, nullifierPk))
	return ConstrainOutputShared(api, utxo, hash, signers)
}

// ConstrainOutputShared classifies the slot, pins dummies, requires a verified
// signer for data-carrying outputs, and binds the public hash to the utxo
// (dummies included — the public hash is the blinded dummy hash). Returns
// Select(isUtxo, utxoHash, 0) for the private-tx-hash chain.
func ConstrainOutputShared(api frontend.API, utxo UtxoCircuitFields, hash frontend.Variable, signers []frontend.Variable) frontend.Variable {
	isUtxo := utxo.IsUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	AssertWhen(api, utxo.isDummy(api), utxo.checkDummy(api))

	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), checkOwnerSigned(api, utxo.Owner, signers))

	utxoHash := UtxoHashCircuit(api, utxo)
	api.AssertIsEqual(utxoHash, hash)

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
}

// checkOwnerSigned returns 1 iff owner is non-zero and equals one of signers,
// so the utxo belongs to an owner whose signature this proof verifies. The
// non-zero requirement keeps zero-masked signer slots from ever matching.
func checkOwnerSigned(api frontend.API, owner frontend.Variable, signers []frontend.Variable) frontend.Variable {
	prod := frontend.Variable(1)
	for _, signer := range signers {
		prod = api.Mul(prod, api.Sub(owner, signer))
	}
	return api.Mul(api.IsZero(prod), api.Sub(1, api.IsZero(owner)))
}

// checkOwnerIsPublicInput — default-zone variants only: returns 1 iff the
// public owner tag recomputes the output owner_hash.
func checkOwnerIsPublicInput(api frontend.API, utxo UtxoCircuitFields, ownerPkHash, nullifierPk frontend.Variable) frontend.Variable {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerPkHash,
		NullifierPk:  nullifierPk,
	})
	return api.IsZero(api.Sub(ownerHash, utxo.Owner))
}
