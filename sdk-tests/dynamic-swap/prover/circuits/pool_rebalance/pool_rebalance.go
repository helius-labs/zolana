// Package pool_rebalance restructures the pool: many pool notes in, many pool
// notes out, with an optional public credit that publishes accumulated
// surplus into available_liquidity.
package pool_rebalance

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Slot counts. The circuit is compiled once at the largest SPP-supported
// transact shape (IN5_OUT4); a rebalance uses 1..5 real inputs and 1..4 real
// outputs and pads the remaining slots with dummy notes (Domain = DummyDomain,
// every other field zero, fresh random blinding), exactly the SPP transfer
// circuit's padding convention. The forwarded transact always declares shape
// 5x4 with AllowDummyInputs set.
const (
	NInputSlots  = 5
	NOutputSlots = 4
)

// Circuit checks, over the real (non-dummy) slots only:
//
//	sum(amount_out) == sum(amount_in)
//	sum(booked_out) == sum(booked_in) + Credit
//	per output: booked <= amount
//
// where booked is each pool note's DataHash. Dummy slots are pinned all-zero
// (except blinding), so they drop out of the sums by construction. The credit
// is therefore capped by the spent notes' surplus -- value provably present
// and not yet counted -- which is what lets the program raise available_liquidity
// by it without ever double counting.
type Circuit struct {
	Public PublicInputs

	In0 spp.UtxoCircuitFields
	In1 spp.UtxoCircuitFields
	In2 spp.UtxoCircuitFields
	In3 spp.UtxoCircuitFields
	In4 spp.UtxoCircuitFields

	Out0 spp.UtxoCircuitFields
	Out1 spp.UtxoCircuitFields
	Out2 spp.UtxoCircuitFields
	Out3 spp.UtxoCircuitFields

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	inputs := []spp.UtxoCircuitFields{c.In0, c.In1, c.In2, c.In3, c.In4}
	outputs := []spp.UtxoCircuitFields{c.Out0, c.Out1, c.Out2, c.Out3}

	inputHashes := make([]frontend.Variable, NInputSlots)
	sumAmountIn := frontend.Variable(0)
	sumBookedIn := frontend.Variable(0)
	for i, utxo := range inputs {
		// Slot 0 must be real so an all-dummy rebalance cannot exist.
		inputHashes[i] = c.checkPoolSlot(api, utxo, i == 0)
		sumAmountIn = api.Add(sumAmountIn, utxo.Amount)
		sumBookedIn = api.Add(sumBookedIn, utxo.DataHash)
	}

	outputHashes := make([]frontend.Variable, NOutputSlots)
	sumAmountOut := frontend.Variable(0)
	sumBookedOut := frontend.Variable(0)
	for i, utxo := range outputs {
		outputHashes[i] = c.checkPoolSlot(api, utxo, i == 0)
		// Per-output invariant booked <= amount. Holds trivially for dummies
		// (0 <= 0), so it is unconditional; both sides are 64-bit-checked in
		// checkPoolSlot.
		api.AssertIsLessOrEqual(utxo.DataHash, utxo.Amount)
		sumAmountOut = api.Add(sumAmountOut, utxo.Amount)
		sumBookedOut = api.Add(sumBookedOut, utxo.DataHash)
	}

	api.ToBinary(c.Public.Credit, 64)
	api.AssertIsEqual(sumAmountOut, sumAmountIn)
	api.AssertIsEqual(sumBookedOut, api.Add(sumBookedIn, c.Public.Credit))

	privateTxHashInputs{
		InputUtxoHashes:  inputHashes,
		OutputUtxoHashes: outputHashes,
		ExternalDataHash: c.ExternalDataHash,
		PrivateTxHash:    c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api)
	return nil
}

// checkPoolSlot constrains one slot as either a real pool note or a dummy and
// returns its contribution to the private-tx-hash chain: the utxo hash for a
// real note, 0 for a dummy -- mirroring the SPP transfer circuit, whose
// private tx hash also zeroes dummy slots.
func (c *Circuit) checkPoolSlot(api frontend.API, utxo spp.UtxoCircuitFields, mustBeReal bool) frontend.Variable {
	isReal := api.IsZero(api.Sub(utxo.Domain, spp.UtxoDomain))
	isDummy := api.IsZero(api.Sub(utxo.Domain, spp.DummyDomain))
	api.AssertIsEqual(api.Add(isReal, isDummy), 1)
	if mustBeReal {
		api.AssertIsEqual(isReal, 1)
	}

	// Dummy: every field except domain and blinding is zero (this is what makes
	// the unconditional sums and the booked <= amount check dummy-safe).
	spp.AssertWhen(api, isDummy, utxo.CheckDummy(api))

	// Real: a pool note of the pair's destination asset, locked under the
	// pool_authority, with booked committed as the data hash.
	spp.AssertWhen(api, isReal, api.IsZero(api.Sub(utxo.Owner, c.Public.PoolAuthorityOwnerHash)))
	spp.AssertWhen(api, isReal, api.IsZero(api.Sub(utxo.Asset, c.Public.DestinationAsset)))
	api.AssertIsEqual(utxo.RingDataHash, 0)
	api.AssertIsEqual(utxo.RingProgramID, 0)
	api.ToBinary(utxo.Amount, 64)
	api.ToBinary(utxo.DataHash, 64)

	utxoHash := spp.UtxoHashCircuit(api, utxo)
	return api.Select(isReal, utxoHash, frontend.Variable(0))
}

// PublicInputs folds PrivateTxHash with the pool_authority owner-hash and the
// destination asset (both recomputed/read on-chain from the pair) and the
// public Credit the program adds to available_liquidity.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash          frontend.Variable
	PoolAuthorityOwnerHash frontend.Variable
	DestinationAsset       frontend.Variable
	// The surplus being published: sum(booked_out) - sum(booked_in), maker
	// chosen up to the spent notes' surplus. 0 is a pure merge/split/re-blind.
	Credit frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.PoolAuthorityOwnerHash,
		p.DestinationAsset,
		p.Credit,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	InputUtxoHashes  []frontend.Variable
	OutputUtxoHashes []frontend.Variable
	ExternalDataHash frontend.Variable
	PrivateTxHash    frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 5-in/4-out, the largest supported shape; dummy slots enter the chains as
	// 0, matching the SPP transfer circuit at the same shape.
	addressHashes := make([]frontend.Variable, NInputSlots)
	for i := range addressHashes {
		addressHashes[i] = frontend.Variable(0)
	}

	privateTxHash := spp.PrivateTxHashCircuit(api, t.InputUtxoHashes, t.OutputUtxoHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}
