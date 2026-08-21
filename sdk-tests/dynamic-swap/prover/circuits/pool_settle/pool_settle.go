// Package pool_settle fills one escrow from the pair's committed liquidity
// pool.
package pool_settle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"circuits/blinding"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit resolves one escrow. The private minimum committed by escrow_open
// selects either an exact-input fill or a full source-asset refund without
// changing the public IN2_OUT3 shape.
//
// 2-in (order, pool note) / 3-out (recipient payout, pool change, maker
// receipt), the exact IN2_OUT3 shape. The payout is funded from the pool: a
// note locked under the pair's pool_authority PDA whose DataHash commits its
// booked value (the portion of its amount the public available_liquidity already
// counts). The change returns to the pool with booked reduced by the full
// max_order_size reservation (clamped at zero) while only owed actually
// leaves, so the unspent reservation stays in the note as surplus --
// publishable later through pool_rebalance's credit. Settle itself moves no
// public liquidity value.
type Circuit struct {
	Public PublicInputs

	OrderIn spp.UtxoCircuitFields
	PoolIn  spp.UtxoCircuitFields

	RecipientOut spp.UtxoCircuitFields
	PoolChange   spp.UtxoCircuitFields
	MakerReceipt spp.UtxoCircuitFields

	OrderAmount        frontend.Variable
	RecipientOwnerHash frontend.Variable
	MinPrice           frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.ToBinary(c.MinPrice, 64)
	orderDataHash := gadget.PoseidonHash(api, []frontend.Variable{c.RecipientOwnerHash, c.MinPrice})
	api.AssertIsEqual(c.OrderIn.DataHash, orderDataHash)
	orderInHash := c.checkOrderInputUtxo(api)
	poolInHash := c.checkPoolInputUtxo(api)

	// Every escrow is priced at creation, so ExecutionPrice is always nonzero;
	// assert it so an uncommitted order can never be proven.
	api.AssertIsDifferent(c.Public.ExecutionPrice, 0)
	api.ToBinary(c.Public.ExecutionPrice, 64)
	api.ToBinary(c.OrderAmount, 64)

	// owed = OrderAmount * ExecutionPrice. Both factors are 64-bit (OrderAmount
	// via the spent order leaf, ExecutionPrice via the program-fed public
	// input), but their product is a free 128-bit value in the field -- pin it
	// to 64 bits so the pool-change subtraction below cannot be satisfied with
	// a wrapped amount. escrow_open already proved owed <= max_order_size when
	// the reservation was taken.
	owed := api.Mul(c.OrderAmount, c.Public.ExecutionPrice)
	api.ToBinary(owed, 64)
	fills := cmp.IsLessOrEqual(api, c.MinPrice, c.Public.ExecutionPrice)
	settledOwed := api.Select(fills, owed, frontend.Variable(0))

	recipientOutHash := c.checkRecipientOutputUtxo(api, fills, owed)
	poolChangeHash := c.checkPoolChangeOutputUtxo(api, settledOwed)
	makerReceiptHash := c.checkMakerReceiptOutputUtxo(api, fills)

	// The recipient blinding derives from the order blinding so the taker
	// precomputes its payout note at creation (owed is fixed by the stored
	// execution_price). The pool change and maker receipt blindings are free
	// maker-chosen witnesses: the maker builds every settle proof itself.
	api.AssertIsEqual(c.RecipientOut.Blinding,
		blinding.DeriveOutputBlinding(api, c.OrderIn.Blinding, blinding.RecipientBlindingDomain))

	privateTxHashInputs{
		OrderInputUtxoHash:         orderInHash,
		PoolInputUtxoHash:          poolInHash,
		RecipientOutputUtxoHash:    recipientOutHash,
		PoolChangeOutputUtxoHash:   poolChangeHash,
		MakerReceiptOutputUtxoHash: makerReceiptHash,
		ExternalDataHash:           c.ExternalDataHash,
		PrivateTxHash:              c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, orderInHash)
	return nil
}

// PublicInputs folds PrivateTxHash, ExecutionPrice (the escrow's stored public
// price), OrderInHash (the witnessed order UTXO's own reconstructed hash,
// asserted equal in Check below), DestinationAsset, the pool_authority
// owner-hash (recomputed on-chain: PDA re-derived, zero-secret nullifier
// pubkey), MaxOrderSize (the pair's immutable reservation size, entering the
// booked clamp), and ReceiptOwnerHash (the maker receipt destination stored on
// the pair). The recipient owner-hash is deliberately NOT here -- it is
// reopened together with the minimum from OrderIn.DataHash, which the public
// OrderInHash pins, so the payout destination is enforced without ever being
// revealed on-chain. The native program recomputes this hash from on-chain state.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash          frontend.Variable
	ExecutionPrice         frontend.Variable
	OrderInHash            frontend.Variable
	DestinationAsset       frontend.Variable
	PoolAuthorityOwnerHash frontend.Variable
	MaxOrderSize           frontend.Variable
	ReceiptOwnerHash       frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.OrderInHash,
		p.DestinationAsset,
		p.PoolAuthorityOwnerHash,
		p.MaxOrderSize,
		p.ReceiptOwnerHash,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash         frontend.Variable
	PoolInputUtxoHash          frontend.Variable
	RecipientOutputUtxoHash    frontend.Variable
	PoolChangeOutputUtxoHash   frontend.Variable
	MakerReceiptOutputUtxoHash frontend.Variable
	ExternalDataHash           frontend.Variable
	PrivateTxHash              frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 2-in/3-out; output order (recipient, pool_change, maker_receipt) must
	// match the native program's output indices and the SDK.
	inputHashes := []frontend.Variable{
		t.OrderInputUtxoHash,
		t.PoolInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.RecipientOutputUtxoHash,
		t.PoolChangeOutputUtxoHash,
		t.MakerReceiptOutputUtxoHash,
	}
	addressHashes := []frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
	}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderIn.RingDataHash, 0)
	api.AssertIsEqual(c.OrderIn.RingProgramID, 0)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return spp.UtxoHashCircuit(api, c.OrderIn)
}

func (c *Circuit) checkPoolInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolIn.RingDataHash, 0)
	api.AssertIsEqual(c.PoolIn.RingProgramID, 0)
	// Only program-locked pool liquidity of the pair's destination asset can
	// fund the payout.
	api.AssertIsEqual(c.PoolIn.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolIn.Asset, c.Public.DestinationAsset)
	// booked_in = the pool note's data hash; pool notes commit booked directly.
	api.ToBinary(c.PoolIn.DataHash, 64)
	return spp.UtxoHashCircuit(api, c.PoolIn)
}

// checkRecipientOutputUtxo pays `owed` of the destination asset to the
// recipient reopened with the minimum from OrderIn.DataHash (pinned by the
// public OrderInHash), so the payout destination is
// enforced without being revealed.
func (c *Circuit) checkRecipientOutputUtxo(api frontend.API, fills, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.RecipientOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RecipientOut.RingDataHash, 0)
	api.AssertIsEqual(c.RecipientOut.RingProgramID, 0)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, api.Select(fills, c.PoolIn.Asset, c.OrderIn.Asset))
	api.AssertIsEqual(c.RecipientOut.Amount, api.Select(fills, owed, c.OrderAmount))
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return spp.UtxoHashCircuit(api, c.RecipientOut)
}

// checkPoolChangeOutputUtxo re-locks the unspent pool value (pool - owed) with
// booked reduced by the full max_order_size reservation, clamped at zero: the
// public accounting charged max_order_size when the escrow was created, so the
// counted value drops by at most that much while only owed actually left. The
// gap (max_order_size - owed, plus any clamp shortfall) stays in the note as
// surplus. The 64-bit range check on the amount rejects an underfunded pool
// note (pool < owed would wrap the field subtraction).
func (c *Circuit) checkPoolChangeOutputUtxo(api frontend.API, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.PoolChange.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolChange.RingDataHash, 0)
	api.AssertIsEqual(c.PoolChange.RingProgramID, 0)
	api.AssertIsEqual(c.PoolChange.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolChange.Asset, c.PoolIn.Asset)

	api.AssertIsEqual(c.PoolChange.Amount, api.Sub(c.PoolIn.Amount, owed))
	api.ToBinary(c.PoolChange.Amount, 64)

	// booked_out = max(booked_in - max_order_size, 0). Pin MaxOrderSize to 64
	// bits before the bounded comparator: cmp.IsLessOrEqual is only
	// well-defined on in-range operands (booked_in is pinned in
	// checkPoolInputUtxo).
	api.ToBinary(c.Public.MaxOrderSize, 64)
	coversReservation := cmp.IsLessOrEqual(api, c.Public.MaxOrderSize, c.PoolIn.DataHash)
	bookedOut := api.Select(coversReservation,
		api.Sub(c.PoolIn.DataHash, c.Public.MaxOrderSize),
		frontend.Variable(0))
	api.AssertIsEqual(c.PoolChange.DataHash, bookedOut)

	return spp.UtxoHashCircuit(api, c.PoolChange)
}

// checkMakerReceiptOutputUtxo pays the settled source asset (the full order
// amount) to the maker receipt owner-hash stored on the pair.
func (c *Circuit) checkMakerReceiptOutputUtxo(api frontend.API, fills frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.MakerReceipt.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerReceipt.RingDataHash, 0)
	api.AssertIsEqual(c.MakerReceipt.RingProgramID, 0)
	api.AssertIsEqual(c.MakerReceipt.DataHash, 0)
	api.AssertIsEqual(c.MakerReceipt.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.MakerReceipt.Amount, api.Select(fills, c.OrderAmount, frontend.Variable(0)))
	api.AssertIsEqual(c.MakerReceipt.Owner, c.Public.ReceiptOwnerHash)
	return spp.UtxoHashCircuit(api, c.MakerReceipt)
}
