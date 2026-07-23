package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type Output struct {
	Utxo UtxoCircuitFields
	Hash frontend.Variable

	// Default-zone variants only: OwnerPkHash is the public owner tag, NullifierPk
	// the witnessed nullifier pubkey; together they recompute Utxo.Owner.
	OwnerPkHash frontend.Variable
	NullifierPk frontend.Variable
}

func (c *Circuit) outputUtxos() []UtxoCircuitFields {
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

// signerOwners collects the owner hash of every real input slot — the
// identities checkOwnership binds to a verified signer. Non-real slots are
// masked to zero, which checkOwnerSigned never matches.
func (c *Circuit) signerOwners(api frontend.API) []frontend.Variable {
	signers := make([]frontend.Variable, len(c.Inputs))
	for i, in := range c.Inputs {
		signers[i] = api.Mul(in.isReal(api), in.Utxo.Owner)
	}
	return signers
}

// constrainDefaultZoneOutput — default zone: a real output must not be a
// member of a zone, and checkOwnerIsPublicInput.
func (c *Circuit) constrainDefaultZoneOutput(api frontend.API, out Output, signers []frontend.Variable) frontend.Variable {
	assertWhen(api, out.isReal(api), out.Utxo.checkNotInZone(api))
	assertWhen(api, out.isReal(api), out.checkOwnerIsPublicInput(api))
	return constrainOutputShared(api, out, signers)
}

// constrainOutputShared verifies one created output and returns its UTXO hash
// (0 for a dummy) for the transaction-hash chain (step 4). An output slot is
// one of two kinds, told apart by the domain tag alone: a created utxo
// (UtxoDomain) or a dummy utxo (DummyDomain); exactly one tag must hold. Every
// output binds its hash; checkDummy holds the dummy-kind checks. A real output
// carrying utxo data must be owned by a signer, so data can only be attached
// to an owner that authorized it.
func constrainOutputShared(api frontend.API, out Output, signers []frontend.Variable) frontend.Variable {
	isReal := out.isReal(api)
	api.AssertIsEqual(api.Add(isReal, out.isDummy(api)), 1)

	assertWhen(api, out.isDummy(api), out.Utxo.checkDummy(api))

	dataIsSet := api.Sub(1, api.IsZero(out.Utxo.DataHash))
	assertWhen(api, api.Mul(isReal, dataIsSet), checkOwnerSigned(api, out.Utxo.Owner, signers))

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	return api.Select(isReal, utxoHash, frontend.Variable(0))
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

// isReal: the slot creates a utxo.
func (out Output) isReal(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, UtxoDomain))
}

func (out Output) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, DummyDomain))
}

// checkOwnerIsPublicInput — default-zone variants only: returns 1 iff the public
// owner tag matches the output owner_hash.
func (out Output) checkOwnerIsPublicInput(api frontend.API) frontend.Variable {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: out.OwnerPkHash,
		NullifierPk:  out.NullifierPk,
	})
	return api.IsZero(api.Sub(ownerHash, out.Utxo.Owner))
}
