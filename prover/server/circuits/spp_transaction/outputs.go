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

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain (step 4). Every output binds its hash;
// checkDummy and checkReal hold the per-kind checks.
func constrainOutput(api frontend.API, out Output, confidential, zone, zoneAuthority bool, zoneProgramID frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)

	assertWhen(api, out.IsDummy, out.checkDummy(api))
	assertWhen(api, out.isReal(api), out.checkReal(api))
	constrainProgramZone(api, out.isReal(api), out.Utxo, zone, zoneAuthority, zoneProgramID)
	if confidential {
		// Check that owner is a public input.
		assertWhen(api, out.isReal(api), out.checkOwnership(api))
	}

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}

// isReal: the slot creates a utxo.
func (out Output) isReal(api frontend.API) frontend.Variable {
	return api.Sub(1, out.IsDummy)
}

// checkDummy — dummy output: returns 1 iff the amount is zero, so the slot
// carries no value; the remaining fields stay free so dummy hashes are
// indistinguishable from real ones.
func (out Output) checkDummy(api frontend.API) frontend.Variable {
	return allZero(api,
		out.Utxo.Asset,
		out.Utxo.Amount,
		out.Utxo.Owner,
		out.Utxo.ZoneDataHash,
		out.Utxo.ZoneProgramID,
	)
}

// checkReal — created output: returns 1 iff the utxo carries the utxo domain.
func (out Output) checkReal(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(out.Utxo.Domain, UtxoDomain))
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
