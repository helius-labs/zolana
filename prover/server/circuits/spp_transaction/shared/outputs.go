package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SignerOwners projects the signer array onto the owner identities it proved:
// the owner hash of every input slot that carries content, which ConstrainInput
// bound to that slot's signer. Slots that carry nothing are masked to 0.
func SignerOwners(api frontend.API, inputs []Input) Signers {
	owners := make(Signers, len(inputs))
	for i, in := range inputs {
		owners[i] = api.Mul(in.isUtxoOrAddress(api), in.Utxo.Owner)
	}
	return owners
}

// ConstrainDefaultZoneOutput — default zone: an output must not be a member
// of a zone, and a real output's owner_hash must recompute from the public
// owner tag (ownerPkHash) and the witnessed nullifierPk. Dummy slots skip the
// owner binding so their public tag stays free. Because the tag is bound to the
// owner, a data-carrying output only needs that tag to be one of the signers.
func ConstrainDefaultZoneOutput(
	api frontend.API,
	utxo UtxoCircuitFields,
	hash, ownerPkHash, nullifierPk frontend.Variable,
	signers Signers,
) frontend.Variable {
	utxo.AssertInDefaultZone(api)
	AssertWhen(api, utxo.IsUtxo(api), checkOwnerIsPublicInput(api, utxo, ownerPkHash, nullifierPk))
	return constrainOutput(api, utxo, hash, signers.Contains(api, ownerPkHash))
}

// ConstrainCustomZoneOutput — custom zone: output owners stay private, so there
// is no public tag to resolve against the signer pk hashes. A data-carrying
// output must instead be owned by one of the owner identities the signers proved.
func ConstrainCustomZoneOutput(api frontend.API, utxo UtxoCircuitFields, hash frontend.Variable, signerOwners Signers) frontend.Variable {
	return constrainOutput(api, utxo, hash, signerOwners.Contains(api, utxo.Owner))
}

// constrainOutput classifies the slot, pins dummies, requires ownerSigned for
// data-carrying outputs, and binds the public hash to the utxo (dummies
// included — the public hash is the blinded dummy hash). Returns
// Select(isUtxo, utxoHash, 0) for the private-tx-hash chain.
func constrainOutput(api frontend.API, utxo UtxoCircuitFields, hash, ownerSigned frontend.Variable) frontend.Variable {
	isUtxo := utxo.IsUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, utxo.isDummy(api)), 1)

	AssertWhen(api, utxo.isDummy(api), utxo.checkDummy(api))

	dataIsSet := api.Sub(1, api.IsZero(utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), ownerSigned)

	utxoHash := UtxoHashCircuit(api, utxo)
	api.AssertIsEqual(utxoHash, hash)

	return api.Select(isUtxo, utxoHash, frontend.Variable(0))
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
