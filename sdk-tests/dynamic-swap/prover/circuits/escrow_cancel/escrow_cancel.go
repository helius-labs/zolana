package escrow_cancel

import (
	"github.com/consensys/gnark/frontend"

	"circuits/blinding"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// RefundBlindingDomain is folded into the refund output's blinding derivation
// (Poseidon(order_blinding, domain), same helper as the settle outputs). It
// MUST stay in sync with dynamic-swap-prover's Rust copy and be distinct from
// the settle domains -- settle's recipient output derives from the same order
// blinding.
const RefundBlindingDomain uint64 = 0x434E4C5245464E44 // "CNLREFND"

// Circuit refunds one expired escrow: 1-in (order UTXO) / 1-out (refund), the
// exact supported IN1_OUT1 shape. The full order amount returns, in the source
// asset, to the recipient committed as OrderIn.DataHash (the taker's
// owner-hash escrow_open wrote there). The expiry gate is program-side (the
// escrow account's created_at plus the pair's expiry_slots), so the circuit
// carries no notion of time. The refund output has no DataHash, which is what
// lets the escrow_authority PDA stay the only owner-signer at IN1_OUT1.
type Circuit struct {
	Public PublicInputs

	OrderIn spp.UtxoCircuitFields

	RefundOut spp.UtxoCircuitFields

	OrderAmount frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	orderInHash := c.checkOrderInputUtxo(api)
	refundOutHash := c.checkRefundOutputUtxo(api)

	privateTxHashInputs{
		OrderInputUtxoHash:   orderInHash,
		RefundOutputUtxoHash: refundOutHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, orderInHash)
	return nil
}

// PublicInputs folds PrivateTxHash with OrderInHash (the witnessed order UTXO's
// own reconstructed hash, asserted equal in Check below). The recipient
// owner-hash is re-opened from OrderIn.DataHash, which OrderInHash pins, so the
// refund destination is enforced without being revealed. The native program
// recomputes this hash from `Escrow.order_utxo_hash`.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	OrderInHash   frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.OrderInHash,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash   frontend.Variable
	RefundOutputUtxoHash frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 1-in/1-out, exactly the supported IN1_OUT1 shape.
	inputHashes := []frontend.Variable{
		t.OrderInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.RefundOutputUtxoHash,
	}
	addressHashes := []frontend.Variable{
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

// checkRefundOutputUtxo returns the full order amount, in the order's (source)
// asset, to the recipient committed as OrderIn.DataHash. The blinding derives
// from the order blinding so the taker precomputes its refund note at creation.
func (c *Circuit) checkRefundOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.RefundOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RefundOut.RingDataHash, 0)
	api.AssertIsEqual(c.RefundOut.RingProgramID, 0)
	api.AssertIsEqual(c.RefundOut.DataHash, 0)
	api.AssertIsEqual(c.RefundOut.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.RefundOut.Amount, c.OrderAmount)
	api.AssertIsEqual(c.RefundOut.Owner, c.OrderIn.DataHash)
	api.AssertIsEqual(c.RefundOut.Blinding,
		blinding.DeriveOutputBlinding(api, c.OrderIn.Blinding, RefundBlindingDomain))
	return spp.UtxoHashCircuit(api, c.RefundOut)
}
