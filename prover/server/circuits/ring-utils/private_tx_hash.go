// Package ringutils holds the squads ring proof circuits. This first circuit
// proves knowledge of a transaction's input and output UTXOs whose hashes fold,
// with the external data hash, into a given private_tx_hash -- the public input
// the ring proof shares with the SPP proof -- and that every UTXO is either
// free or a member of the public RingProgramID.
package ringutils

import (
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// NumInputs and NumOutputs fix the circuit shape. The HashChain folds exactly
// these many UTXO hashes, so a proved transaction must have matching counts.
const (
	NumInputs  = 2
	NumOutputs = 2
)

// Utxo is the witness of one UTXO. It carries the precomputed owner_hash, the
// data and ring-program hashes, and the raw id of its tree; the circuit hashes
// the UTXO, matching zolana_transaction's Utxo::hash.
type Utxo struct {
	TreeID          frontend.Variable
	OwnerHash       frontend.Variable
	Asset           frontend.Variable
	Amount          frontend.Variable
	Blinding        frontend.Variable
	ProgramDataHash frontend.Variable
	RingDataHash    frontend.Variable
	RingProgramID   frontend.Variable
}

// Hash recomputes the UTXO hash from the witnessed owner_hash and fields.
func (u Utxo) Hash(api frontend.API) frontend.Variable {
	return transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain:        transaction.UtxoDomain,
		Owner:         u.OwnerHash,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.ProgramDataHash,
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
	}, u.TreeID)
}

// PublicInputs are the ring circuit's public inputs. RingProgramID is the
// verifying ring program's pk_field; a UTXO with a non-zero ring id must carry
// it, so a proof cannot be replayed against another ring.
type PublicInputs struct {
	PrivateTxHash frontend.Variable `gnark:",public"`
	RingProgramID frontend.Variable `gnark:",public"`
}

// assertRingMemberOrFree constrains the UTXO's ring id to 0 or ringProgramID.
func (u Utxo) assertRingMemberOrFree(api frontend.API, ringProgramID frontend.Variable) {
	api.AssertIsEqual(api.Mul(u.RingProgramID, api.Sub(u.RingProgramID, ringProgramID)), 0)
}

// PrivateTxHashCircuit proves the witnessed inputs and outputs fold, with the
// external data hash and the private transaction blinding, into the public
// PrivateTxHash.
type PrivateTxHashCircuit struct {
	Public            PublicInputs
	Inputs            [NumInputs]Utxo
	Outputs           [NumOutputs]Utxo
	AddressHashes     [NumInputs]frontend.Variable
	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *PrivateTxHashCircuit) Define(api frontend.API) error {
	inputHashes := make([]frontend.Variable, NumInputs)
	for i := range c.Inputs {
		c.Inputs[i].assertRingMemberOrFree(api, c.Public.RingProgramID)
		inputHashes[i] = c.Inputs[i].Hash(api)
	}
	outputHashes := make([]frontend.Variable, NumOutputs)
	for i := range c.Outputs {
		c.Outputs[i].assertRingMemberOrFree(api, c.Public.RingProgramID)
		outputHashes[i] = c.Outputs[i].Hash(api)
	}
	addressHashes := make([]frontend.Variable, NumInputs)
	for i := range c.AddressHashes {
		addressHashes[i] = c.AddressHashes[i]
	}
	h := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(c.Public.PrivateTxHash, h)
	return nil
}
