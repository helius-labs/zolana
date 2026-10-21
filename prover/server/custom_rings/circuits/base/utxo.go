package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// UtxoWires opens one transaction slot, its owner is Poseidon(OwnerPkHash, NullifierPk).
type UtxoWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

type OpenedUtxo struct {
	// Hash is the commitment SPP publishes or spends, a dummy's included.
	Hash frontend.Variable
	Utxo frontend.Variable
	// Owner is 0 on a dummy, the owner SPP pins there.
	Owner frontend.Variable
}

// Open hashes the slot as SPP does, so a ring proof binds the commitment SPP publishes or spends.
func (w UtxoWires) Open(api frontend.API) OpenedUtxo {
	utxo := api.IsZero(api.Sub(w.Domain, shared.UtxoDomain))
	owner := api.Mul(utxo, gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk}))
	hash := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         owner,
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	}, w.TreeID)
	return OpenedUtxo{Hash: hash, Utxo: utxo, Owner: owner}
}
