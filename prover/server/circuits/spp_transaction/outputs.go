package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain (step 5). In the confidential variant it
// also binds the public owner tag to the output owner_hash.
func constrainOutput(api frontend.API, out Output, confidential, zone, zoneAuthority bool, zoneProgramID frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	assertZeroWhen(api, out.IsDummy, out.Utxo.Amount)
	assertEqualWhen(api, notDummy, out.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, notDummy, out.Utxo, zone, zoneAuthority, zoneProgramID)

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	if confidential {
		ownerHash := abstractor.Call(api, OwnerHashGadget{
			OwnerKeyHash: out.OwnerPkHash,
			NullifierPk:  out.NullifierPk,
		})
		assertEqualWhen(api, notDummy, ownerHash, out.Utxo.Owner)
	}

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}
