// Package squadsutils holds the squads ring proof circuits. private_tx_hash is
// the public input a ring proof shares with the SPP proof.
package squadsutils

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

// Utxo is the witness of one UTXO. It carries the precomputed owner_hash and the
// data and ring-program hashes. The circuit hashes the UTXO, matching
// zolana_transaction's Utxo::hash.
type Utxo struct {
	OwnerHash       frontend.Variable
	Asset           frontend.Variable
	Amount          frontend.Variable
	Blinding        frontend.Variable
	ProgramDataHash frontend.Variable
	RingDataHash    frontend.Variable
	RingProgramID   frontend.Variable
}

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
	})
}

type PublicInputs struct {
	PrivateTxHash frontend.Variable `gnark:",public"`
	RingProgramID frontend.Variable `gnark:",public"`
}

// PrivateTxHashCircuit proves the witnessed inputs and outputs fold, with the
// external data hash, into the public PrivateTxHash.
type PrivateTxHashCircuit struct {
	Public           PublicInputs
	Inputs           [NumInputs]Utxo
	Outputs          [NumOutputs]Utxo
	AddressHashes    [NumInputs]frontend.Variable
	ExternalDataHash frontend.Variable
}

func (c *PrivateTxHashCircuit) Define(api frontend.API) error {
	inputHashes := make([]frontend.Variable, NumInputs)
	for i := range c.Inputs {
		inputHashes[i] = c.Inputs[i].Hash(api)
	}
	outputHashes := make([]frontend.Variable, NumOutputs)
	for i := range c.Outputs {
		outputHashes[i] = c.Outputs[i].Hash(api)
	}
	addressHashes := make([]frontend.Variable, NumInputs)
	for i := range c.AddressHashes {
		addressHashes[i] = c.AddressHashes[i]
	}
	h := transaction.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, c.ExternalDataHash)
	api.AssertIsEqual(c.Public.PrivateTxHash, h)
	_ = c.Public.RingProgramID
	return nil
}
