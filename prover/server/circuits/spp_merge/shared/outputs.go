package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// constrainOutput assembles and hashes the single merged output: a bare UTXO
// owned by user_owner_hash carrying the merged asset and the amount summed from
// the inputs. Its leaf fields are shared/constant except the free Blinding (and,
// on the zone rail, ZoneDataHash), so nothing beyond those is witnessed. The
// merged output is always real, so no dummy gating applies. Returns its UTXO hash
// for the private-transaction-hash chain.
func constrainOutput(
	api frontend.API,
	out Output,
	userOwnerHash,
	asset,
	amount,
	zoneProgramID frontend.Variable,
) frontend.Variable {
	// The merged amount is assembled from the input sum, not witnessed. Range-check
	// it to 64 bits (pairs with the per-input checks so sum(inputs) == output holds
	// over the integers, not just mod p).
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: amount})

	utxo := transaction.UtxoCircuitFields{
		Domain:        UtxoDomain,
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        amount,
		Blinding:      out.Blinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  out.ZoneDataHash,
		ZoneProgramID: zoneProgramID,
	}
	return transaction.UtxoHashCircuit(api, utxo)
}
