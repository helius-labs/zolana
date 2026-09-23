package gnarksdk

import (
	"github.com/consensys/gnark/frontend"

	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Utxo is one UTXO's witness, in the field order and with the field names
// zolana-gnark-ffi-prover's utxo_witness_entries writes. TreeID is the raw u16
// id of the tree the UTXO lives in: the tree an input is spent from, the tree
// an output is appended to.
type Utxo struct {
	Domain        frontend.Variable
	Owner         frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
	TreeID        frontend.Variable
}

// Hash is the UTXO hash the shielded pool commits.
func (u Utxo) Hash(api frontend.API) frontend.Variable {
	return spp.UtxoHashCircuit(api, spp.UtxoCircuitFields{
		Domain:        u.Domain,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
	}, u.TreeID)
}

// AssertDefaultRing asserts u is a spendable UTXO outside every ring. Amount
// and TreeID are not range-checked: the transact proof checks both for every
// UTXO hash it folds into the same private transaction hash.
func (u Utxo) AssertDefaultRing(api frontend.API) {
	api.AssertIsEqual(u.Domain, spp.UtxoDomain)
	api.AssertIsEqual(u.RingDataHash, 0)
	api.AssertIsEqual(u.RingProgramID, 0)
}
