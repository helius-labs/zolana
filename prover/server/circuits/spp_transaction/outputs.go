package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

func (c *Circuit) assertOutputs(api frontend.API) []frontend.Variable {
	zone := !c.Confidential
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		outputHashes[i] = constrainOutput(api, c.Outputs[i], c.Confidential, zone, c.ZoneAuthority, c.ZoneProgramID)
	}
	return outputHashes
}

// constrainOutput verifies one created output and returns its UTXO hash (0 for
// a dummy) for the transaction-hash chain (step 4). An output slot is one of
// two kinds, told apart by the domain tag alone: a created utxo (UtxoDomain)
// or a dummy utxo (DummyDomain); exactly one tag must hold. Every output binds
// its hash; checkDummy holds the dummy-kind checks.
func constrainOutput(api frontend.API, out Output, confidential, zone, zoneAuthority bool, zoneProgramID frontend.Variable) frontend.Variable {
	isReal := out.isReal(api)
	api.AssertIsEqual(api.Add(isReal, out.isDummy(api)), 1)

	assertWhen(api, out.isDummy(api), out.Utxo.checkDummy(api))
	constrainProgramZone(api, isReal, out.Utxo, zone, zoneAuthority, zoneProgramID)
	if confidential {
		// Check that owner is a public input.
		assertWhen(api, isReal, out.checkOwnership(api))
	}

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

// checkOwnership — confidential variant only: returns 1 iff the public owner
// tag matches the output owner_hash.
func (out Output) checkOwnership(api frontend.API) frontend.Variable {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: out.OwnerPkHash,
		NullifierPk:  out.NullifierPk,
	})
	return api.IsZero(api.Sub(ownerHash, out.Utxo.Owner))
}

func constrainProgramZone(api frontend.API, notDummy frontend.Variable, u UtxoCircuitFields, zone, strictZone bool, zoneProgramID frontend.Variable) {
	if zone {
		if strictZone { // Whats a strict zone?
			assertEqualWhen(api, notDummy, u.ZoneProgramID, zoneProgramID)
		} else {
			bindIfSet(api, notDummy, u.ZoneProgramID, zoneProgramID)
		}
		requireIdWhenDataSet(api, notDummy, u.ZoneDataHash, u.ZoneProgramID)
	} else {
		assertZeroWhen(api, notDummy, u.ZoneDataHash)
		assertZeroWhen(api, notDummy, u.ZoneProgramID)
	}
}
func bindIfSet(api frontend.API, notDummy, field, public frontend.Variable) {
	isSet := api.Sub(1, api.IsZero(field))
	assertEqualWhen(api, api.Mul(notDummy, isSet), field, public)
}

func requireIdWhenDataSet(api frontend.API, notDummy, dataHash, id frontend.Variable) {
	dataIsSet := api.Sub(1, api.IsZero(dataHash))
	assertZeroWhen(api, api.Mul(notDummy, dataIsSet), api.IsZero(id))
}
