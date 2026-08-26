// Package pool_withdraw unshields a public amount of the destination asset
// from one pool note.
package pool_withdraw

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit spends one pool note into one pool change note, the exact supported
// IN1_OUT1 shape. The public SPL leg is the transact's SplWithdrawal interface
// transfer (the SPP transfer circuit balances it); this circuit's job is the
// booked accounting: the change note keeps booked_in - amount, and the 64-bit
// range checks reject both an overdrawn amount and a negative booked, so a
// withdrawal can only consume counted value. The native program rejects a
// zero amount before proof verification.
type Circuit struct {
	Public PublicInputs

	PoolIn  spp.UtxoCircuitFields
	PoolOut spp.UtxoCircuitFields

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	poolInHash := c.checkPoolInputUtxo(api)
	poolOutHash := c.checkPoolChangeOutputUtxo(api)

	privateTxHashInputs{
		PoolInputUtxoHash:        poolInHash,
		PoolChangeOutputUtxoHash: poolOutHash,
		ExternalDataHash:         c.ExternalDataHash,
		PrivateTxHash:            c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api)
	return nil
}

// PublicInputs folds PrivateTxHash with the pool_authority owner-hash (the
// native program recomputes it: PDA re-derived, zero-secret nullifier pubkey),
// the pair's destination asset, and the withdrawn Amount the program pays out
// through the SplWithdrawal leg and subtracts from available_liquidity.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	// The pool_authority PDA's owner-hash, bound to both pool notes so only
	// program-locked liquidity can fund a withdrawal and the change stays
	// locked.
	PoolAuthorityOwnerHash frontend.Variable
	// The pair's destination asset, fed on-chain from Pair.destination_asset.
	DestinationAsset frontend.Variable
	// The public withdrawn amount, fed on-chain from the instruction data (the
	// program checks it against available_liquidity and the SplWithdrawal leg).
	Amount frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.PoolAuthorityOwnerHash,
		p.DestinationAsset,
		p.Amount,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	PoolInputUtxoHash        frontend.Variable
	PoolChangeOutputUtxoHash frontend.Variable
	ExternalDataHash         frontend.Variable
	PrivateTxHash            frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 1-in/1-out, exactly the supported IN1_OUT1 shape.
	inputHashes := []frontend.Variable{
		t.PoolInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.PoolChangeOutputUtxoHash,
	}
	addressHashes := []frontend.Variable{
		frontend.Variable(0),
	}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkPoolInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolIn.RingDataHash, 0)
	api.AssertIsEqual(c.PoolIn.RingProgramID, 0)
	api.AssertIsEqual(c.PoolIn.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolIn.Asset, c.Public.DestinationAsset)
	// booked_in = the pool note's data hash; pool notes commit booked directly.
	api.ToBinary(c.PoolIn.DataHash, 64)
	return spp.UtxoHashCircuit(api, c.PoolIn)
}

// checkPoolChangeOutputUtxo keeps the remainder locked in the pool with the
// withdrawn value consumed from booked: amount and booked both drop by the
// public Amount, and the 64-bit range checks reject wrap-around, so a
// withdrawal can neither overdraw the note nor exceed its counted value.
func (c *Circuit) checkPoolChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolOut.RingDataHash, 0)
	api.AssertIsEqual(c.PoolOut.RingProgramID, 0)
	api.AssertIsEqual(c.PoolOut.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolOut.Asset, c.Public.DestinationAsset)

	api.AssertIsEqual(c.PoolOut.Amount, api.Sub(c.PoolIn.Amount, c.Public.Amount))
	api.ToBinary(c.PoolOut.Amount, 64)

	api.AssertIsEqual(c.PoolOut.DataHash, api.Sub(c.PoolIn.DataHash, c.Public.Amount))
	api.ToBinary(c.PoolOut.DataHash, 64)

	return spp.UtxoHashCircuit(api, c.PoolOut)
}
