// Package pool_settle fills one escrow from the pair's committed liquidity
// pool.
package pool_settle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/gnarksdk"
)

// blindingSeedDomain ("DSTX") separates the settle blinding seed from
// escrow_cancel's, which derives from the same order blinding. Matches the
// SDK's settle_blinding_seed.
const blindingSeedDomain = 0x44535458

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

	OrderIn gnarksdk.Utxo
	PoolIn  gnarksdk.Utxo

	RecipientOut gnarksdk.Utxo
	PoolChange   gnarksdk.Utxo
	MakerReceipt gnarksdk.Utxo

	OrderAmount        frontend.Variable
	RecipientOwnerHash frontend.Variable
	MinPrice           frontend.Variable

	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.ToBinary(c.MinPrice, 64)
	api.AssertIsEqual(c.OrderIn.DataHash, gnarksdk.Poseidon(api, c.RecipientOwnerHash, c.MinPrice))
	orderInHash := c.checkOrderInputUtxo(api)
	poolInHash := c.checkPoolInputUtxo(api)

	// The taker and the maker both hold the order opening, so the taker can
	// recompute its payout note without a ciphertext. The native program reads
	// FirstNullifier from SPP input 0, so the maker cannot substitute a seed
	// that prevents the recipient's recovery. SPP derives every output
	// blinding of one transaction from the same seed, so the pool change and
	// maker receipt blindings are derivable by the taker as well.
	blindingSeed := gnarksdk.Poseidon(api, blindingSeedDomain, c.OrderIn.Blinding)
	gnarksdk.AssertTransactionBlindings(
		api,
		c.Public.FirstNullifier,
		blindingSeed,
		c.PrivateTxBlinding,
		c.RecipientOut.Blinding,
		c.PoolChange.Blinding,
		c.MakerReceipt.Blinding,
	)

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

	// 2-in/3-out; output order (recipient, pool_change, maker_receipt) must
	// match the native program's output indices and the SDK.
	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{orderInHash, poolInHash},
		[]frontend.Variable{recipientOutHash, poolChangeHash, makerReceiptHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api, orderInHash)
	return nil
}

// PublicInputs folds PrivateTxHash, ExecutionPrice (the escrow's stored public
// price), OrderInHash (the witnessed order UTXO's own reconstructed hash,
// asserted equal in Check below), DestinationAsset, the pool_authority
// owner-hash (recomputed on-chain: PDA re-derived, zero-secret nullifier
// pubkey), MaxOrderSize (the pair's immutable reservation size, entering the
// booked clamp), ReceiptOwnerHash (the maker receipt destination stored on
// the pair), and FirstNullifier (SPP input 0's nullifier, which every output
// blinding derives from). The recipient owner-hash is deliberately NOT here --
// it is reopened together with the minimum from OrderIn.DataHash, which the
// public OrderInHash pins, so the payout destination is enforced without ever
// being revealed on-chain. The native program recomputes this hash from
// on-chain state.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash          frontend.Variable
	ExecutionPrice         frontend.Variable
	OrderInHash            frontend.Variable
	DestinationAsset       frontend.Variable
	PoolAuthorityOwnerHash frontend.Variable
	MaxOrderSize           frontend.Variable
	ReceiptOwnerHash       frontend.Variable
	FirstNullifier         frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	publicInputHash := gnarksdk.Poseidon(
		api,
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.OrderInHash,
		p.DestinationAsset,
		p.PoolAuthorityOwnerHash,
		p.MaxOrderSize,
		p.ReceiptOwnerHash,
		p.FirstNullifier,
	)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API) frontend.Variable {
	c.OrderIn.AssertDefaultRing(api)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return c.OrderIn.Hash(api)
}

func (c *Circuit) checkPoolInputUtxo(api frontend.API) frontend.Variable {
	c.PoolIn.AssertDefaultRing(api)
	// Only program-locked pool liquidity of the pair's destination asset can
	// fund the payout.
	api.AssertIsEqual(c.PoolIn.Owner, c.Public.PoolAuthorityOwnerHash)
	api.AssertIsEqual(c.PoolIn.Asset, c.Public.DestinationAsset)
	// booked_in = the pool note's data hash; pool notes commit booked directly.
	api.ToBinary(c.PoolIn.DataHash, 64)
	return c.PoolIn.Hash(api)
}

// checkRecipientOutputUtxo pays `owed` of the destination asset to the
// recipient reopened with the minimum from OrderIn.DataHash (pinned by the
// public OrderInHash), so the payout destination is
// enforced without being revealed.
func (c *Circuit) checkRecipientOutputUtxo(api frontend.API, fills, owed frontend.Variable) frontend.Variable {
	c.RecipientOut.AssertDefaultRing(api)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, api.Select(fills, c.PoolIn.Asset, c.OrderIn.Asset))
	api.AssertIsEqual(c.RecipientOut.Amount, api.Select(fills, owed, c.OrderAmount))
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return c.RecipientOut.Hash(api)
}

// checkPoolChangeOutputUtxo re-locks the unspent pool value (pool - owed) with
// booked reduced by the full max_order_size reservation, clamped at zero: the
// public accounting charged max_order_size when the escrow was created, so the
// counted value drops by at most that much while only owed actually left. The
// gap (max_order_size - owed, plus any clamp shortfall) stays in the note as
// surplus. The 64-bit range check on the amount rejects an underfunded pool
// note (pool < owed would wrap the field subtraction).
func (c *Circuit) checkPoolChangeOutputUtxo(api frontend.API, owed frontend.Variable) frontend.Variable {
	c.PoolChange.AssertDefaultRing(api)
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

	return c.PoolChange.Hash(api)
}

// checkMakerReceiptOutputUtxo pays the settled source asset (the full order
// amount) to the maker receipt owner-hash stored on the pair.
func (c *Circuit) checkMakerReceiptOutputUtxo(api frontend.API, fills frontend.Variable) frontend.Variable {
	c.MakerReceipt.AssertDefaultRing(api)
	api.AssertIsEqual(c.MakerReceipt.DataHash, 0)
	api.AssertIsEqual(c.MakerReceipt.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.MakerReceipt.Amount, api.Select(fills, c.OrderAmount, frontend.Variable(0)))
	api.AssertIsEqual(c.MakerReceipt.Owner, c.Public.ReceiptOwnerHash)
	return c.MakerReceipt.Hash(api)
}
