package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain (step 5). In the confidential variant it
// also binds the public owner tag to the output owner_hash.
func constrainOutput(api frontend.API, out Output, confidential, zone, zoneAuthority bool, programID, zoneProgramID frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	// A program-owned output (owner == program_id) carries program data and is
	// public to the program, so it skips the confidential owner-tag binding. A
	// user-owned output carries no program data.
	programSet := api.Sub(1, api.IsZero(programID))
	ownerIsProgram := api.IsZero(api.Sub(out.Utxo.Owner, programID))
	isProgramOwned := api.Mul(notDummy, api.Mul(ownerIsProgram, programSet))
	userOwnedReal := api.Sub(notDummy, isProgramOwned)

	assertZeroWhen(api, out.IsDummy, out.Utxo.Amount)
	assertEqualWhen(api, notDummy, out.Utxo.Domain, UtxoDomain)
	// Program data only on program-owned outputs; program identity is the owner,
	// so the standalone program_id field is pinned to 0 on every real output.
	assertZeroWhen(api, userOwnedReal, out.Utxo.DataHash)
	assertZeroWhen(api, notDummy, out.Utxo.ProgramID)
	constrainProgramZone(api, notDummy, out.Utxo, zone, zoneAuthority, zoneProgramID)

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	if confidential {
		ownerHash := abstractor.Call(api, OwnerHashGadget{
			OwnerKeyHash: out.OwnerPkHash,
			NullifierPk:  out.NullifierPk,
		})
		assertEqualWhen(api, userOwnedReal, ownerHash, out.Utxo.Owner)
	}

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}
