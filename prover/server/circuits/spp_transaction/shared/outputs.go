package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type Output struct {
	Utxo UtxoCircuitFields
	Hash frontend.Variable // TODO: move to public inputs struct

	// Default-zone variants only: OwnerPkHash is the public owner tag, NullifierPk
	// the witnessed nullifier pubkey; together they recompute Utxo.Owner.
	OwnerPkHash frontend.Variable
	NullifierPk frontend.Variable
}

func (c *Circuit) OutputUtxos() []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].Utxo
	}
	return out
}

func (c *Circuit) OutputHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].Hash
	}
	return out
}

func (c *Circuit) OutputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].OwnerPkHash
	}
	return out
}

// SignerOwners collects the owner hash of every real input slot — the
// identities checkOwnership binds to a verified signer. Non-real slots are
// masked to zero, which checkOwnerSigned never matches.
func (c *Circuit) SignerOwners(api frontend.API) []frontend.Variable {
	signers := make([]frontend.Variable, len(c.Inputs))
	for i, in := range c.Inputs {
		signers[i] = api.Mul(in.isUtxoOrAddress(api), in.Utxo.Owner)
	}
	return signers
}

// ConstrainDefaultZoneOutput — default zone: a real output must not be a
// member of a zone, and checkOwnerIsPublicInput.
func (c *Circuit) ConstrainDefaultZoneOutput(api frontend.API, out Output, signers []frontend.Variable) frontend.Variable {
	out.Utxo.AssertInDefaultZone(api)
	out.checkOwnerIsPublicInput(api)
	return ConstrainOutputShared(api, out, signers)
}

func ConstrainOutputShared(api frontend.API, out Output, signers []frontend.Variable) frontend.Variable {
	isUtxo := out.IsUtxo(api)
	api.AssertIsEqual(api.Add(isUtxo, out.isDummy(api)), 1)

	AssertWhen(api, out.isDummy(api), out.Utxo.checkDummy(api))

	dataIsSet := api.Sub(1, api.IsZero(out.Utxo.DataHash))
	AssertWhen(api, api.Mul(isUtxo, dataIsSet), checkOwnerSigned(api, out.Utxo.Owner, signers))

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

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

// IsUtxo: the slot creates a utxo.
func (out Output) IsUtxo(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, UtxoDomain))
}

func (out Output) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, DummyDomain))
}

// checkOwnerIsPublicInput — default-zone variants only: returns 1 iff the public
// owner tag matches the output owner_hash.
func (out Output) checkOwnerIsPublicInput(api frontend.API) {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: out.OwnerPkHash,
		NullifierPk:  out.NullifierPk,
	})
	api.AssertIsEqual(ownerHash, out.Utxo.Owner)
}
