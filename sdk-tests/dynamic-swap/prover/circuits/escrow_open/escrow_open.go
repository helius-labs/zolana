package escrow_open

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit binds create_escrow's 2-in/3-out real shape (taker's source UTXO +
// maker's funding UTXO spent; order, reservation, and maker-change UTXOs
// created), the exact supported IN2_OUT3 shape with no padding on either side.
// Both inputs are user-owned and separately authorized (the taker signs
// SourceIn, the maker signs MakerFunding). Requires the source input to match
// OrderAmount exactly (no taker change output): create_escrow's instruction data
// already sits at Solana's whole-transaction size limit, so each side
// pre-consolidates its own note off the create path. OrderAmount is the one
// private witness shared across the order UTXO's amount, the reservation's
// worst-case size (order_amount * max_price), and the maker-change decrement.
type Circuit struct {
	Public PublicInputs

	SourceIn     spp.UtxoCircuitFields
	MakerFunding spp.UtxoCircuitFields

	OrderOut       spp.UtxoCircuitFields
	ReservationOut spp.UtxoCircuitFields
	MakerChange    spp.UtxoCircuitFields

	OrderAmount frontend.Variable

	// MaxPrice is a private witness (not a public input): it is committed into
	// OrderOut.DataHash and later re-opened by escrow_settle, but never revealed
	// on-chain -- keeping it private is what hides the eventual settle-vs-refund
	// outcome.
	MaxPrice frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.OrderAmount, 0)

	// MaxPrice is a free private witness, so pin it to 64 bits. Without this the
	// prover could pick a field-sized MaxPrice whose product OrderAmount*MaxPrice
	// still reduces to a valid 64-bit reservation, then commit that garbage value
	// into OrderOut.DataHash -- where escrow_settle re-opens it and feeds it to a
	// bounded comparator (ExecutionPrice <= MaxPrice), whose result is undefined
	// on an out-of-range operand. Bounding it here (the value's origin) makes it
	// 64-bit everywhere it is later re-opened from the same DataHash.
	api.ToBinary(c.MaxPrice, 64)

	sourceInHash := c.checkSourceInputUtxo(api)
	makerFundingHash := c.checkMakerFundingInputUtxo(api)

	orderOutHash := c.checkOrderOutputUtxo(api)
	reservationOutHash := c.checkReservationOutputUtxo(api, orderOutHash)
	makerChangeHash := c.checkMakerChangeOutputUtxo(api)

	privateTxHashInputs{
		SourceInputUtxoHash:       sourceInHash,
		MakerFundingInputUtxoHash: makerFundingHash,
		OrderOutputUtxoHash:       orderOutHash,
		ReservationOutputUtxoHash: reservationOutHash,
		MakerChangeOutputUtxoHash: makerChangeHash,
		ExternalDataHash:          c.ExternalDataHash,
		PrivateTxHash:             c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api)
	return nil
}

// PublicInputs folds PrivateTxHash with the escrow term visible to the program
// (CreatedAt), the escrow_authority owner-hash, and the two asset bindings
// (SourceAsset, DestinationAsset). MaxPrice is a private witness, committed only
// into OrderOut.DataHash, which is what hides the eventual settle-vs-refund
// outcome. The recipient is NOT here either: it is bound in-circuit to
// SourceIn.Owner (the taker whose funds are escrowed) and committed only into
// OrderOut.DataHash, so it stays as confidential as MaxPrice -- see
// checkOrderOutputUtxo.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	CreatedAt     frontend.Variable
	// The escrow_authority PDA's owner-hash, recomputed on-chain by the native
	// program and bound to OrderOut.Owner (and thus ReservationOut.Owner). Without
	// it OrderOut.Owner is a free witness and a caller could mint the escrow/
	// reservation UTXOs to an owner it controls, then spend the maker-funded
	// reservation directly.
	EscrowAuthorityOwnerHash frontend.Variable
	// The pair's source asset, fed on-chain from Pair.source_asset and bound to
	// SourceIn.Asset. Without it a caller could escrow a worthless token and
	// extract the destination asset on settle.
	SourceAsset frontend.Variable
	// The pair's destination asset, fed on-chain from Pair.destination_asset and
	// bound to MakerFunding.Asset (and thus ReservationOut/MakerChange). Without it
	// the maker could fund with a worthless token that the taker would be paid on
	// settle.
	DestinationAsset frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.CreatedAt,
		p.EscrowAuthorityOwnerHash,
		p.SourceAsset,
		p.DestinationAsset,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	SourceInputUtxoHash       frontend.Variable
	MakerFundingInputUtxoHash frontend.Variable
	OrderOutputUtxoHash       frontend.Variable
	ReservationOutputUtxoHash frontend.Variable
	MakerChangeOutputUtxoHash frontend.Variable
	ExternalDataHash          frontend.Variable
	PrivateTxHash             frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// The real shape is 2-in/3-out, exactly the supported IN2_OUT3 shape --
	// no padding needed on either side. Output order (order, reservation,
	// maker_change) must match the native program's output indices and the SDK.
	inputHashes := []frontend.Variable{
		t.SourceInputUtxoHash,
		t.MakerFundingInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.OrderOutputUtxoHash,
		t.ReservationOutputUtxoHash,
		t.MakerChangeOutputUtxoHash,
	}
	addressHashes := []frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
	}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkSourceInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.SourceIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.SourceIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.SourceIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.SourceIn.DataHash, 0)
	// Bind the escrowed asset to the pair's source asset so a worthless token
	// cannot stand in for it.
	api.AssertIsEqual(c.SourceIn.Asset, c.Public.SourceAsset)
	// No change output: the source input must be exactly OrderAmount.
	api.AssertIsEqual(c.SourceIn.Amount, c.OrderAmount)
	return spp.UtxoHashCircuit(api, c.SourceIn)
}

func (c *Circuit) checkMakerFundingInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.MakerFunding.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerFunding.ZoneDataHash, 0)
	api.AssertIsEqual(c.MakerFunding.ZoneProgramID, 0)
	api.AssertIsEqual(c.MakerFunding.DataHash, 0)
	// Bind the maker's funding asset to the pair's destination asset so the maker
	// cannot fund with a worthless token that the taker would be paid on settle.
	api.AssertIsEqual(c.MakerFunding.Asset, c.Public.DestinationAsset)
	return spp.UtxoHashCircuit(api, c.MakerFunding)
}

// checkOrderOutputUtxo commits (recipient, MaxPrice, CreatedAt) into the order
// UTXO's DataHash so settle can later re-derive the same escrow terms from the
// UTXO alone. The recipient is bound to SourceIn.Owner: the escrow's payout on
// settle/refund goes to the same party whose source funds are being escrowed (the
// taker), enforced in-circuit rather than trusted from a caller-supplied field --
// SourceIn.Owner is pinned to the real spent source leaf via SourceInputUtxoHash
// -> PrivateTxHash. OrderOut.Owner is bound to the public EscrowAuthorityOwnerHash
// (and ReservationOut.Owner is tied to it in checkReservationOutputUtxo), so both
// order and reservation UTXOs are provably owned by the pair's escrow_authority
// PDA -- only the native program can spend them, via settle.
func (c *Circuit) checkOrderOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderOut.Owner, c.Public.EscrowAuthorityOwnerHash)
	api.AssertIsEqual(c.OrderOut.Asset, c.SourceIn.Asset)
	api.AssertIsEqual(c.OrderOut.Amount, c.OrderAmount)
	api.AssertIsEqual(c.OrderOut.DataHash, gadget.PoseidonHash(api, []frontend.Variable{
		c.SourceIn.Owner,
		c.MaxPrice,
		c.Public.CreatedAt,
	}))
	return spp.UtxoHashCircuit(api, c.OrderOut)
}

// checkReservationOutputUtxo binds the reservation's DataHash to the order UTXO's
// own hash, so settle can prove in-circuit that the reservation UTXO it spends
// really belongs to this specific order. The reservation is the maker's worst-case
// liquidity (order_amount * max_price) in the destination asset, escrowed under the
// escrow_authority PDA.
func (c *Circuit) checkReservationOutputUtxo(api frontend.API, orderOutHash frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.ReservationOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.ReservationOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.ReservationOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.ReservationOut.Asset, c.MakerFunding.Asset)
	api.AssertIsEqual(c.ReservationOut.Owner, c.OrderOut.Owner)
	api.AssertIsEqual(c.ReservationOut.DataHash, orderOutHash)

	api.AssertIsEqual(c.ReservationOut.Amount, api.Mul(c.OrderAmount, c.MaxPrice))

	return spp.UtxoHashCircuit(api, c.ReservationOut)
}

// checkMakerChangeOutputUtxo returns the maker's unspent funding (funding -
// reserved) to the maker's own note -- same asset and owner as MakerFunding, so a
// co-signing taker cannot redirect it. The 64-bit range check rejects an
// over-reservation (funding < reserved would wrap the field subtraction).
func (c *Circuit) checkMakerChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.MakerChange.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerChange.ZoneDataHash, 0)
	api.AssertIsEqual(c.MakerChange.ZoneProgramID, 0)
	api.AssertIsEqual(c.MakerChange.DataHash, 0)
	api.AssertIsEqual(c.MakerChange.Asset, c.MakerFunding.Asset)
	api.AssertIsEqual(c.MakerChange.Owner, c.MakerFunding.Owner)

	reserved := api.Mul(c.OrderAmount, c.MaxPrice)
	api.AssertIsEqual(c.MakerChange.Amount, api.Sub(c.MakerFunding.Amount, reserved))
	api.ToBinary(c.MakerChange.Amount, 64)

	return spp.UtxoHashCircuit(api, c.MakerChange)
}
