package transaction

import "github.com/consensys/gnark/frontend"

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain (step 5).
func constrainOutput(api frontend.API, out Output) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	assertZeroWhen(api, out.IsDummy, out.Utxo.Amount)
	assertEqualWhen(api, notDummy, out.Utxo.Domain, UtxoDomain)
	// Default transact creates only bare UTXOs (no program/policy/zone data).
	assertZeroWhen(api, notDummy, out.Utxo.DataHash)
	assertZeroWhen(api, notDummy, out.Utxo.ZoneDataHash)
	assertZeroWhen(api, notDummy, out.Utxo.ZoneProgramID)

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	assertEqualWhen(api, notDummy, utxoHash, out.Hash)
	assertZeroWhen(api, out.IsDummy, out.Hash)

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}
