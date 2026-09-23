package escrow_settle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/gnarksdk"
)

const blindingSeedDomain = 0x44535458 // DSTX; matches the SDK's settle_blinding_seed.

// Circuit resolves an escrow -- settle or price-refund -- in a single circuit/VK
// so the resolving transaction never reveals which outcome occurred. The proof
// shape, account list, and verifying key are identical in both cases; the
// outcome is derived inside Define and is NOT observable, because MaxPrice is a
// private witness (bound to the order UTXO's DataHash) rather than a public
// input:
//
//	isSettle = (ExecutionPrice <= MaxPrice)
//
// Every escrow is priced at creation (commit is folded into create_escrow), so
// ExecutionPrice is always nonzero -- asserted below, an uncommitted order can
// never be proven. An order with an acceptable price settles; one whose price
// moved past MaxPrice refunds; settle and refund are indistinguishable on-chain.
//
// 2-in (order, reservation) / 3-out (recipient, maker_counter, maker_source), the
// exact IN2_OUT3 shape. There is no shared pool: the reservation input alone funds
// the recipient's payout and the maker's counter-asset change. On refund,
// MakerSource is a zero-amount output rather than an omitted one, so the shape
// does not differ between outcomes.
type Circuit struct {
	Public PublicInputs

	OrderIn       gnarksdk.Utxo
	ReservationIn gnarksdk.Utxo

	RecipientOut gnarksdk.Utxo
	MakerCounter gnarksdk.Utxo
	MakerSource  gnarksdk.Utxo

	OrderAmount frontend.Variable

	// RecipientOwnerHash, MaxPrice, and CreatedAt are private witnesses, bound to
	// OrderIn.DataHash (= Poseidon(RecipientOwnerHash, MaxPrice, CreatedAt), the
	// same commitment escrow_open wrote). Keeping MaxPrice private is what hides
	// settle-vs-refund: an observer knows the public ExecutionPrice but not the
	// threshold it is compared against. RecipientOwnerHash stays private too -- it
	// is the taker's owner-hash (= the source UTXO's owner escrow_open committed),
	// pinned by the public OrderInHash and bound to RecipientOut.Owner below, so
	// the payout destination is enforced without ever being revealed on-chain.
	RecipientOwnerHash frontend.Variable
	MaxPrice           frontend.Variable
	CreatedAt          frontend.Variable

	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	orderInHash := c.checkOrderInputUtxo(api)
	// The escrow creator and settler both hold these openings. The first
	// nullifier is read from SPP instruction data by the native program, so the
	// settler cannot substitute a seed that prevents the recipient's recovery.
	blindingSeed := gnarksdk.Poseidon(api, blindingSeedDomain, c.OrderIn.Blinding, c.ReservationIn.Blinding)
	gnarksdk.AssertTransactionBlindings(
		api,
		c.Public.FirstNullifier,
		blindingSeed,
		c.PrivateTxBlinding,
		c.RecipientOut.Blinding,
		c.MakerCounter.Blinding,
		c.MakerSource.Blinding,
	)

	// Bind the private MaxPrice/CreatedAt to the order UTXO's committed DataHash
	// so the prover cannot choose a MaxPrice that flips the outcome. OrderInHash
	// is public and pins OrderIn's whole hash (incl. DataHash), so a false
	// MaxPrice cannot satisfy this equality.
	api.AssertIsEqual(c.OrderIn.DataHash, gnarksdk.Poseidon(api, c.RecipientOwnerHash, c.MaxPrice, c.CreatedAt))

	// Pin MaxPrice to 64 bits before the bounded comparator below: cmp
	// .IsLessOrEqual is only well-defined on in-range operands, so an out-of-
	// range MaxPrice would let the prover force isSettle either way. escrow_open
	// already bounds the value committed into DataHash, but this makes the
	// comparator's precondition locally explicit rather than cross-circuit.
	api.ToBinary(c.MaxPrice, 64)

	// Every escrow is priced at creation, so ExecutionPrice is always nonzero;
	// assert it so an uncommitted order can never be proven (rather than routing
	// a zero price to a free settle). The outcome is then purely the price
	// comparison against the private MaxPrice.
	api.AssertIsDifferent(c.Public.ExecutionPrice, 0)
	isSettle := cmp.IsLessOrEqual(api, c.Public.ExecutionPrice, c.MaxPrice)

	// Settle: owed = OrderAmount * ExecutionPrice, remainder = reserved - owed.
	// Refund: owed = 0, remainder = reserved (the full reservation credited back
	// to the maker). reserved (order_amount * max_price) is fixed at reservation
	// time.
	settleOwed := api.Mul(c.OrderAmount, c.Public.ExecutionPrice)
	owed := api.Select(isSettle, settleOwed, 0)
	reserved := api.Mul(c.OrderAmount, c.MaxPrice)
	remainder := api.Sub(reserved, owed)

	reservationInHash := c.checkReservationInputUtxo(api, reserved)

	// Settle: RecipientOut pays `owed` of the reservation's (destination) asset.
	// Refund: RecipientOut pays the full OrderAmount back in the order's (source)
	// asset. RecipientOwnerHash is identical either way.
	recipientAmount := api.Select(isSettle, owed, c.OrderAmount)
	recipientAsset := api.Select(isSettle, c.ReservationIn.Asset, c.OrderIn.Asset)
	recipientOutHash := c.checkRecipientOutputUtxo(api, recipientAmount, recipientAsset)

	// The maker's counter-asset leg: the unspent reservation (remainder) returns
	// to the maker. Replaces the old pool output -- there is no pool UTXO to add.
	makerCounterHash := c.checkMakerCounterOutputUtxo(api, remainder)

	// Settle: MakerSource receives OrderAmount of the settled source asset.
	// Refund: MakerSource is a zero-amount output -- present in both cases so the
	// shape never differs, but valueless when refunding.
	makerSourceAmount := api.Select(isSettle, c.OrderAmount, 0)
	makerSourceHash := c.checkMakerSourceOutputUtxo(api, makerSourceAmount)

	// 2-in/3-out; output order (recipient, maker_counter, maker_source) must match
	// the native program's output indices and the SDK.
	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{orderInHash, reservationInHash},
		[]frontend.Variable{recipientOutHash, makerCounterHash, makerSourceHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api, orderInHash, reservationInHash)
	return nil
}

// PublicInputs folds PrivateTxHash and ExecutionPrice (the public pair price the
// native program reads from the escrow account) with OrderInHash and
// ReservationInHash (the witnessed input UTXOs' own reconstructed hashes,
// asserted equal in Check below), plus AuthorityOwnerHash (without which
// MakerCounter/MakerSource's Owner fields would be free witnesses a prover could
// redirect). MaxPrice and RecipientOwnerHash are deliberately NOT here -- both are
// private witnesses bound via OrderIn.DataHash: MaxPrice keeps the settle-vs-refund
// outcome hidden, and RecipientOwnerHash keeps the payout destination confidential
// (the public OrderInHash pins the DataHash, so neither can be forged). The native
// program recomputes this hash from on-chain state (`Escrow.execution_price`,
// `Escrow.escrow_utxo_hash`, `Escrow.reservation_utxo_hash`,
// `Pair.authority_owner_hash`).
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash      frontend.Variable
	ExecutionPrice     frontend.Variable
	OrderInHash        frontend.Variable
	ReservationInHash  frontend.Variable
	AuthorityOwnerHash frontend.Variable
	FirstNullifier     frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash, reservationInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	api.AssertIsEqual(p.ReservationInHash, reservationInHash)
	publicInputHash := gnarksdk.Poseidon(
		api,
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.OrderInHash,
		p.ReservationInHash,
		p.AuthorityOwnerHash,
		p.FirstNullifier,
	)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API) frontend.Variable {
	c.OrderIn.AssertDefaultRing(api)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return c.OrderIn.Hash(api)
}

func (c *Circuit) checkReservationInputUtxo(api frontend.API, reserved frontend.Variable) frontend.Variable {
	c.ReservationIn.AssertDefaultRing(api)
	api.AssertIsEqual(c.ReservationIn.Amount, reserved)
	return c.ReservationIn.Hash(api)
}

func (c *Circuit) checkRecipientOutputUtxo(api frontend.API, amount, asset frontend.Variable) frontend.Variable {
	c.RecipientOut.AssertDefaultRing(api)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, asset)
	api.AssertIsEqual(c.RecipientOut.Amount, amount)
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return c.RecipientOut.Hash(api)
}

// checkMakerCounterOutputUtxo is the maker's counter-asset leg: the unspent
// reservation (remainder) returned to the maker's own note. It replaces the old
// pool output -- there is no pool UTXO, so the amount is exactly `remainder`, not
// pool_in + remainder. Asset is the reservation's (destination) asset.
func (c *Circuit) checkMakerCounterOutputUtxo(api frontend.API, remainder frontend.Variable) frontend.Variable {
	c.MakerCounter.AssertDefaultRing(api)
	api.AssertIsEqual(c.MakerCounter.DataHash, 0)
	api.AssertIsEqual(c.MakerCounter.Asset, c.ReservationIn.Asset)
	api.AssertIsEqual(c.MakerCounter.Owner, c.Public.AuthorityOwnerHash)

	api.AssertIsEqual(c.MakerCounter.Amount, remainder)
	api.ToBinary(c.MakerCounter.Amount, 64)

	return c.MakerCounter.Hash(api)
}

// checkMakerSourceOutputUtxo is the pair authority's (maker's) own shielded UTXO
// receiving the settled source asset on a settle outcome. On a refund outcome
// `amount` is 0: the output is still produced (so the shape never differs between
// outcomes) but carries no value.
func (c *Circuit) checkMakerSourceOutputUtxo(api frontend.API, amount frontend.Variable) frontend.Variable {
	c.MakerSource.AssertDefaultRing(api)
	api.AssertIsEqual(c.MakerSource.DataHash, 0)
	api.AssertIsEqual(c.MakerSource.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.MakerSource.Amount, amount)
	api.AssertIsEqual(c.MakerSource.Owner, c.Public.AuthorityOwnerHash)
	return c.MakerSource.Hash(api)
}
