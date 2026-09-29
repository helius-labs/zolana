package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	transaction "zolana/prover/circuits/spp_transaction/shared"
)

func constrainOutput(
	api frontend.API,
	out Output,
	hash,
	blinding,
	userOwnerHash,
	asset,
	amount,
	ringProgramID,
	treeID frontend.Variable,
) {

	abstractor.CallVoid(api, transaction.RangeCheck64{Value: amount})

	utxo := transaction.UtxoCircuitFields{
		Domain:        UtxoDomain,
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        amount,
		Blinding:      blinding,
		DataHash:      frontend.Variable(0),
		RingDataHash:  out.RingDataHash,
		RingProgramID: ringProgramID,
	}
	transaction.ConstrainOutput(api, utxo, hash, frontend.Variable(0), treeID)
}
