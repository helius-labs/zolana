package escrow_cancel

import (
	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

// blindingSeedDomain ("DCNL") separates the refund blinding seed from
// pool_settle's, which derives from the same order blinding. Matches the SDK's
// cancel_blinding_seed.
const blindingSeedDomain = 0x44434e4c

// Circuit refunds one expired escrow: 1-in (order UTXO) / 1-out (refund), the
// exact supported IN1_OUT1 shape. The full order amount returns, in the source
// asset, to the recipient reopened with the private minimum from
// OrderIn.DataHash. The expiry gate is program-side (the
// escrow account's created_at plus the pair's expiry_slots), so the circuit
// carries no notion of time. The refund output has no DataHash, which is what
// lets the escrow_authority PDA stay the only owner-signer at IN1_OUT1.
type Circuit struct {
	Public PublicInputs

	OrderIn gnarksdk.Utxo

	RefundOut gnarksdk.Utxo

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
	refundOutHash := c.checkRefundOutputUtxo(api)

	// The refund blinding derives from the order opening, so the taker
	// recomputes its refund note without a ciphertext. The native program reads
	// FirstNullifier from SPP input 0, so a canceller cannot substitute a seed
	// that prevents the recipient's recovery.
	blindingSeed := gnarksdk.Poseidon(api, blindingSeedDomain, c.OrderIn.Blinding)
	gnarksdk.AssertTransactionBlindings(
		api,
		c.Public.FirstNullifier,
		blindingSeed,
		c.PrivateTxBlinding,
		c.RefundOut.Blinding,
	)

	// 1-in/1-out, exactly the supported IN1_OUT1 shape.
	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{orderInHash},
		[]frontend.Variable{refundOutHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api, orderInHash)
	return nil
}

// PublicInputs folds PrivateTxHash with OrderInHash (the witnessed order UTXO's
// own reconstructed hash, asserted equal in Check below) and FirstNullifier
// (SPP input 0's nullifier, which the refund blinding derives from). The
// recipient and minimum reopen OrderIn.DataHash, which OrderInHash pins, so the
// refund destination is enforced without being revealed. The native program
// recomputes this hash from `Escrow.order_utxo_hash` and the SPP instruction
// data.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash  frontend.Variable
	OrderInHash    frontend.Variable
	FirstNullifier frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	publicInputHash := gnarksdk.Poseidon(api, p.PrivateTxHash, p.OrderInHash, p.FirstNullifier)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API) frontend.Variable {
	c.OrderIn.AssertDefaultRing(api)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return c.OrderIn.Hash(api)
}

// checkRefundOutputUtxo returns the full order amount, in the order's (source)
// asset, to the recipient reopened from OrderIn.DataHash.
func (c *Circuit) checkRefundOutputUtxo(api frontend.API) frontend.Variable {
	c.RefundOut.AssertDefaultRing(api)
	api.AssertIsEqual(c.RefundOut.DataHash, 0)
	api.AssertIsEqual(c.RefundOut.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.RefundOut.Amount, c.OrderAmount)
	api.AssertIsEqual(c.RefundOut.Owner, c.RecipientOwnerHash)
	return c.RefundOut.Hash(api)
}
