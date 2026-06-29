package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	transaction "zolana/prover/circuits/spp_transaction"
)

// constrainOutput verifies the single merged output: it is a bare UTXO owned by
// user_owner_hash, and its commitment matches the public output_utxo_hash. The
// merged output is always real, so no dummy gating applies. Returns its UTXO
// hash for the private-transaction-hash chain.
func constrainOutput(api frontend.API, out Output, userOwnerHash frontend.Variable, zone bool, zoneProgramID frontend.Variable) frontend.Variable {
	api.AssertIsEqual(out.Utxo.Domain, UtxoDomain)

	api.AssertIsEqual(out.Utxo.DataHash, 0)
	if zone {
		api.AssertIsEqual(out.Utxo.ZoneProgramID, zoneProgramID)
	} else {
		api.AssertIsEqual(out.Utxo.ZoneDataHash, 0)
		api.AssertIsEqual(out.Utxo.ZoneProgramID, 0)
	}

	// Output well-formed: owner == user_owner_hash.
	api.AssertIsEqual(out.Utxo.Owner, userOwnerHash)

	// Range-check the merged amount to 64 bits (pairs with the per-input checks
	// so sum(inputs) == output holds over the integers, not just mod p).
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: out.Utxo.Amount})

	utxoHash := transaction.UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)

	return utxoHash
}
