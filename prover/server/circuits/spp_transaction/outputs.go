package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

func (c *Circuit) assertOutputs(api frontend.API) []frontend.Variable {
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		if c.Confidential {
			outputHashes[i] = c.constrainDefaultZoneOutput(api, c.Outputs[i])
		} else {
			outputHashes[i] = c.constrainZoneOutput(api, c.Outputs[i])
		}
	}
	return outputHashes
}

// constrainDefaultZoneOutput — default zone: a real output must not be a
// member of a zone, and checkOwnerIsPublicInput.
func (c *Circuit) constrainDefaultZoneOutput(api frontend.API, out Output) frontend.Variable {
	assertWhen(api, out.isReal(api), out.Utxo.checkNotInZone(api))
	assertWhen(api, out.isReal(api), out.checkOwnerIsPublicInput(api))
	return constrainOutputShared(api, out)
}

// constrainZoneOutput — custom zone: a real output is either owned by the
// public zone or not a member of any zone; the zone-authority variant requires
// zone ownership for every real output.
func (c *Circuit) constrainZoneOutput(api frontend.API, out Output) frontend.Variable {
	if c.ZoneAuthority {
		assertWhen(api, out.isReal(api), c.checkZoneMember(api, out.Utxo))
	} else {
		assertWhen(api, out.isReal(api), c.checkZoneMemberOrFree(api, out.Utxo))
	}
	return constrainOutputShared(api, out)
}

// constrainOutputShared verifies one created output and returns its UTXO hash
// (0 for a dummy) for the transaction-hash chain (step 4). An output slot is
// one of two kinds, told apart by the domain tag alone: a created utxo
// (UtxoDomain) or a dummy utxo (DummyDomain); exactly one tag must hold. Every
// output binds its hash; checkDummy holds the dummy-kind checks.
func constrainOutputShared(api frontend.API, out Output) frontend.Variable {
	isReal := out.isReal(api)
	api.AssertIsEqual(api.Add(isReal, out.isDummy(api)), 1)

	assertWhen(api, out.isDummy(api), out.Utxo.checkDummy(api))

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	return api.Select(isReal, utxoHash, frontend.Variable(0))
}

// isReal: the slot creates a utxo.
func (out Output) isReal(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, UtxoDomain))
}

// isDummy: the slot is padding and carries nothing.
func (out Output) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, DummyDomain))
}

// checkOwnerIsPublicInput — confidential variant only: returns 1 iff the public owner
// tag matches the output owner_hash.
func (out Output) checkOwnerIsPublicInput(api frontend.API) frontend.Variable {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: out.OwnerPkHash,
		NullifierPk:  out.NullifierPk,
	})
	return api.IsZero(api.Sub(ownerHash, out.Utxo.Owner))
}
