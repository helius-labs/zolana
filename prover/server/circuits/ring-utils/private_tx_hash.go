// Package ringutils holds the squads ring proof circuits. This first circuit
// proves knowledge of a transaction's input and output UTXOs whose hashes fold,
// with the external data hash, into a given private_tx_hash -- the public input
// the ring proof shares with the SPP proof -- and that every UTXO is either
// free or a member of the public RingProgramID. Slot categories mirror SPP:
// only real UTXOs enter the chains, dummies contribute 0, and address slots
// enter the separate address-nullifier chain as opaque values.
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

// Utxo is the witness of one UTXO slot. It carries the slot domain, the
// precomputed owner_hash, the data and ring-program hashes, and the raw id of
// its tree; the circuit hashes the UTXO, matching zolana_transaction's
// Utxo::hash.
//
// Domain is the SPP slot domain (transaction.UtxoDomain, DummyDomain, or, for
// inputs, AddressDomain). SPP folds only UtxoDomain slots into the input and
// output chains and contributes 0 for every other slot, so this circuit must
// select the same way or a transaction with a padding dummy could never be
// proven against its SPP private_tx_hash. SPP already constrains a dummy's
// fields to zero; here the slot is selected out, so its fields are irrelevant.
type Utxo struct {
	Domain          frontend.Variable
	TreeID          frontend.Variable
	OwnerHash       frontend.Variable
	Asset           frontend.Variable
	Amount          frontend.Variable
	Blinding        frontend.Variable
	ProgramDataHash frontend.Variable
	RingDataHash    frontend.Variable
	RingProgramID   frontend.Variable
}

// isUtxo: the slot is a real UTXO that enters its hash chain.
func (u Utxo) isUtxo(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, transaction.UtxoDomain))
}

// chainElement is the slot's contribution to its private_tx_hash chain: the
// UTXO hash for a real UTXO, 0 for a dummy or address slot, as in SPP.
func (u Utxo) chainElement(api frontend.API) frontend.Variable {
	return api.Select(u.isUtxo(api), u.Hash(api), frontend.Variable(0))
}

// Hash recomputes the UTXO hash from the witnessed domain, owner_hash and fields.
func (u Utxo) Hash(api frontend.API) frontend.Variable {
	return transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain:        u.Domain,
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
// PrivateTxHash. AddressNullifiers mirrors the SPP address category: the
// nullifier (compressed address) of every address slot, 0 elsewhere. The values
// are opaque here; SPP constrains them.
type PrivateTxHashCircuit struct {
	Public            PublicInputs
	Inputs            [NumInputs]Utxo
	Outputs           [NumOutputs]Utxo
	AddressNullifiers [NumInputs]frontend.Variable
	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *PrivateTxHashCircuit) Define(api frontend.API) error {
	inputHashes := make([]frontend.Variable, NumInputs)
	for i := range c.Inputs {
		c.Inputs[i].assertRingMemberOrFree(api, c.Public.RingProgramID)
		inputHashes[i] = c.Inputs[i].chainElement(api)
	}
	outputHashes := make([]frontend.Variable, NumOutputs)
	for i := range c.Outputs {
		c.Outputs[i].assertRingMemberOrFree(api, c.Public.RingProgramID)
		outputHashes[i] = c.Outputs[i].chainElement(api)
	}
	addressNullifiers := make([]frontend.Variable, NumInputs)
	for i := range c.AddressNullifiers {
		addressNullifiers[i] = c.AddressNullifiers[i]
	}
	h := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressNullifiers,
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(c.Public.PrivateTxHash, h)
	return nil
}
