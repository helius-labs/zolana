// Package pool_deposit moves a public amount of the depositor's shielded
// destination asset into one new pool note that books the full amount.
package pool_deposit

import (
	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

// Circuit spends the depositor's source note into one pool note. SPP proves the
// transaction at IN1_OUT2 with a compact second output, which publishes hash 0
// and so leaves PrivateTxHash unchanged; any other real input or output would
// change that hash and fail the proof. The transact carries no public
// transfer, so the source note holds exactly the deposited Amount of the
// destination asset and the pool note takes all of it, booked in full: the
// program adds Amount to available_liquidity.
//
// The program signs the transact as the pool authority, which owns the
// data-bearing pool note, so the source must not be a pool note: re-depositing
// a pool note would book the same tokens twice. Proofless deposits cannot carry
// the booked data hash, so liquidity enters the pool through this proven
// transact; the depositor shields the amount to itself first. The native
// program rejects a zero amount before proof verification.
type Circuit struct {
	Public PublicInputs

	SourceIn gnarksdk.Utxo
	PoolOut  gnarksdk.Utxo

	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	sourceInHash := c.checkSourceInputUtxo(api)
	poolOutHash := c.checkPoolOutputUtxo(api)

	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{sourceInHash},
		[]frontend.Variable{poolOutHash},
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api)
	return nil
}

// PublicInputs folds PrivateTxHash with the pool_authority owner-hash (the
// native program recomputes it: PDA re-derived, zero-secret nullifier pubkey),
// the pair's destination asset, and the deposited Amount the program adds to
// available_liquidity.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	// The pool_authority PDA's owner-hash, bound to the pool note so the
	// deposit stays program-locked, and excluded as the source owner.
	PoolAuthorityOwnerHash frontend.Variable
	// The pair's destination asset, fed on-chain from Pair.destination_asset.
	DestinationAsset frontend.Variable
	// The public deposited amount, fed on-chain from the instruction data.
	Amount frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gnarksdk.Poseidon(
		api,
		p.PrivateTxHash,
		p.PoolAuthorityOwnerHash,
		p.DestinationAsset,
		p.Amount,
	)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

// checkSourceInputUtxo pins the spent note to exactly the deposited amount of
// the destination asset, owned by anyone but the pool. SPP proves its
// ownership and inclusion.
func (c *Circuit) checkSourceInputUtxo(api frontend.API) frontend.Variable {
	c.SourceIn.AssertDefaultRing(api)
	api.AssertIsDifferent(c.SourceIn.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.SourceIn.Asset, c.Public.DestinationAsset)
	api.AssertIsEqual(c.SourceIn.Amount, c.Public.Amount)
	return c.SourceIn.Hash(api)
}

// checkPoolOutputUtxo pins the new pool note: pool-owned, in the destination
// asset, holding exactly the deposited amount and booking all of it.
func (c *Circuit) checkPoolOutputUtxo(api frontend.API) frontend.Variable {
	c.PoolOut.AssertDefaultRing(api)
	api.AssertIsEqual(c.PoolOut.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolOut.Asset, c.Public.DestinationAsset)

	api.AssertIsEqual(c.PoolOut.Amount, c.Public.Amount)
	api.ToBinary(c.PoolOut.Amount, 64)
	// booked = the pool note's data hash; pool notes commit booked directly.
	api.AssertIsEqual(c.PoolOut.DataHash, c.Public.Amount)

	return c.PoolOut.Hash(api)
}
