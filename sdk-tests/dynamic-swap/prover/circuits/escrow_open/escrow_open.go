package escrow_open

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit binds create_escrow's taker-only 1-in/2-out shape (taker's source UTXO
// spent; order and taker-change UTXOs created), the exact supported IN1_OUT2
// shape with no padding on either side. The taker signs SourceIn as the CPI
// payer; the program signs the escrow-authority-owned order output, which
// authorizes the data-bearing slot. The maker is not involved: its committed
// pool liquidity is reserved program-side (available_liquidity -= max_order_size)
// and enters only at settle time, so there is no funding input and no maker
// change here -- the circuit's liquidity job is only the owed cap, which makes
// the worst-case reservation sufficient. The live pair price is deliberately
// absent: the program checks it against the public floor's configured window.
type Circuit struct {
	Public PublicInputs

	SourceIn spp.UtxoCircuitFields

	OrderOut    spp.UtxoCircuitFields
	TakerChange spp.UtxoCircuitFields

	OrderAmount frontend.Variable
	MinPrice    frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.ToBinary(c.OrderAmount, 64)
	api.ToBinary(c.MinPrice, 64)
	api.ToBinary(c.Public.PublicPriceFloor, 64)
	api.ToBinary(c.Public.PriceTolerance, 64)
	api.ToBinary(c.Public.MinOrderAmount, 64)
	api.ToBinary(c.Public.MaxOrderSize, 64)
	api.AssertIsLessOrEqual(c.Public.MinOrderAmount, c.OrderAmount)

	// The private exact sell limit may be stricter than the public floor, but
	// not outside the quote-time half of the pair's symmetric public window.
	referencePrice := api.Add(c.Public.PublicPriceFloor, c.Public.PriceTolerance)
	coveragePrice := api.Add(referencePrice, c.Public.PriceTolerance)
	api.ToBinary(referencePrice, 64)
	api.ToBinary(coveragePrice, 64)
	api.AssertIsLessOrEqual(c.Public.PublicPriceFloor, c.MinPrice)
	api.AssertIsLessOrEqual(c.MinPrice, referencePrice)

	// Reserve against the highest price the program can accept. The product is
	// pinned to u64 before comparison so field wraparound cannot satisfy it.
	worstCaseOwed := api.Mul(c.OrderAmount, coveragePrice)
	api.ToBinary(worstCaseOwed, 64)
	api.AssertIsLessOrEqual(worstCaseOwed, c.Public.MaxOrderSize)

	sourceInHash := c.checkSourceInputUtxo(api)
	orderOutHash := c.checkOrderOutputUtxo(api)
	takerChangeHash := c.checkTakerChangeOutputUtxo(api)

	privateTxHashInputs{
		SourceInputUtxoHash:       sourceInHash,
		OrderOutputUtxoHash:       orderOutHash,
		TakerChangeOutputUtxoHash: takerChangeHash,
		ExternalDataHash:          c.ExternalDataHash,
		PrivateTxHash:             c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api)
	return nil
}

// PublicInputs folds PrivateTxHash with the escrow_authority owner-hash and the
// pair's source-asset binding. The recipient is NOT here: it is bound in-circuit
// to SourceIn.Owner (the taker whose funds are escrowed) and committed as the
// order UTXO's DataHash, so the payout destination stays confidential -- see
// checkOrderOutputUtxo.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	// The escrow_authority PDA's owner-hash, recomputed on-chain by the native
	// program (PDA re-derived, nullifier pubkey the hardcoded zero-secret
	// constant) and bound to OrderOut.Owner. Without it OrderOut.Owner is a free
	// witness and a caller could mint the order UTXO to an owner it controls,
	// then spend it directly instead of through settle/cancel.
	EscrowAuthorityOwnerHash frontend.Variable
	// The pair's source asset, fed on-chain from Pair.source_asset and bound to
	// SourceIn.Asset. Without it a caller could escrow a worthless token and
	// extract the destination asset on settle.
	SourceAsset frontend.Variable
	// Public quote window policy, fed on-chain from instruction data and the pair.
	PublicPriceFloor frontend.Variable
	PriceTolerance   frontend.Variable
	MinOrderAmount   frontend.Variable
	// The pair's immutable max_order_size, fed on-chain from Pair.max_order_size.
	// Caps the worst-case covered payout so the fixed reservation is sufficient.
	MaxOrderSize frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.EscrowAuthorityOwnerHash,
		p.SourceAsset,
		p.PublicPriceFloor,
		p.PriceTolerance,
		p.MinOrderAmount,
		p.MaxOrderSize,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	SourceInputUtxoHash       frontend.Variable
	OrderOutputUtxoHash       frontend.Variable
	TakerChangeOutputUtxoHash frontend.Variable
	ExternalDataHash          frontend.Variable
	PrivateTxHash             frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// The real shape is 1-in/2-out, exactly the supported IN1_OUT2 shape --
	// no padding needed on either side. Output order (order, taker_change) must
	// match the native program's output index and the SDK.
	inputHashes := []frontend.Variable{
		t.SourceInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.OrderOutputUtxoHash,
		t.TakerChangeOutputUtxoHash,
	}
	addressHashes := []frontend.Variable{
		frontend.Variable(0),
	}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkSourceInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.SourceIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.SourceIn.RingDataHash, 0)
	api.AssertIsEqual(c.SourceIn.RingProgramID, 0)
	api.AssertIsEqual(c.SourceIn.DataHash, 0)
	// Bind the escrowed asset to the pair's source asset so a worthless token
	// cannot stand in for it.
	api.AssertIsEqual(c.SourceIn.Asset, c.Public.SourceAsset)
	return spp.UtxoHashCircuit(api, c.SourceIn)
}

// checkOrderOutputUtxo commits the recipient and private minimum as the order
// UTXO's DataHash so settle and cancel can later reopen them from the UTXO
// alone. The recipient is bound to SourceIn.Owner: the payout goes to the same
// party whose source funds are being escrowed (the taker), enforced in-circuit
// rather than trusted from a caller-supplied field -- SourceIn.Owner is pinned
// to the real spent source leaf via SourceInputUtxoHash -> PrivateTxHash.
// OrderOut.Owner is bound to the public EscrowAuthorityOwnerHash, so the order
// UTXO is provably owned by the pair's escrow_authority PDA -- only the native
// program can spend it, via settle or cancel.
func (c *Circuit) checkOrderOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderOut.RingDataHash, 0)
	api.AssertIsEqual(c.OrderOut.RingProgramID, 0)
	api.AssertIsEqual(c.OrderOut.Owner, c.Public.EscrowAuthorityOwnerHash)
	api.AssertIsEqual(c.OrderOut.Asset, c.SourceIn.Asset)
	api.AssertIsEqual(c.OrderOut.Amount, c.OrderAmount)
	orderDataHash := gadget.PoseidonHash(api, []frontend.Variable{c.SourceIn.Owner, c.MinPrice})
	api.AssertIsEqual(c.OrderOut.DataHash, orderDataHash)
	return spp.UtxoHashCircuit(api, c.OrderOut)
}

// checkTakerChangeOutputUtxo returns the unescrowed remainder (source - order)
// to the taker's own note -- same asset and owner as SourceIn. The 64-bit range
// check rejects an over-escrow (source < order would wrap the field
// subtraction).
func (c *Circuit) checkTakerChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.TakerChange.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.TakerChange.RingDataHash, 0)
	api.AssertIsEqual(c.TakerChange.RingProgramID, 0)
	api.AssertIsEqual(c.TakerChange.DataHash, 0)
	api.AssertIsEqual(c.TakerChange.Asset, c.SourceIn.Asset)
	api.AssertIsEqual(c.TakerChange.Owner, c.SourceIn.Owner)

	api.AssertIsEqual(c.TakerChange.Amount, api.Sub(c.SourceIn.Amount, c.OrderAmount))
	api.ToBinary(c.TakerChange.Amount, 64)

	return spp.UtxoHashCircuit(api, c.TakerChange)
}
