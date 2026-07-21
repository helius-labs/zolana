package escrow_settle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
)

// Per-output-slot domains folded into DeriveOutputBlinding so the three settle
// outputs derive independent blindings from the same pair of input blindings.
// These constants MUST stay in sync with dynamic-swap-prover's Rust copies.
const (
	RecipientBlindingDomain    uint64 = 0x5345545245434950 // "SETRECIP"
	MakerCounterBlindingDomain uint64 = 0x5345544D4B435452 // "SETMKCTR"
	MakerSourceBlindingDomain  uint64 = 0x5345544D4B535243 // "SETMKSRC"
)

// settleBlindingBits truncates the Poseidon output to a 31-byte blinding (the
// SPP Blinding width), matching the Rust derivation's [1..32] byte slice.
const settleBlindingBits = 248

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

	OrderIn       spp.UtxoCircuitFields
	ReservationIn spp.UtxoCircuitFields

	RecipientOut spp.UtxoCircuitFields
	MakerCounter spp.UtxoCircuitFields
	MakerSource  spp.UtxoCircuitFields

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

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	orderInHash := c.checkOrderInputUtxo(api)

	// Bind the private MaxPrice/CreatedAt to the order UTXO's committed DataHash
	// so the prover cannot choose a MaxPrice that flips the outcome. OrderInHash
	// is public and pins OrderIn's whole hash (incl. DataHash), so a false
	// MaxPrice cannot satisfy this equality.
	api.AssertIsEqual(c.OrderIn.DataHash, gadget.PoseidonHash(api, []frontend.Variable{
		c.RecipientOwnerHash,
		c.MaxPrice,
		c.CreatedAt,
	}))

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

	// Every output UTXO's blinding is deterministically derived from BOTH escrow
	// input blindings (the order and reservation notes). Only a holder of both
	// input secrets can recompute these, so the maker and taker can find and
	// spend their settle outputs without an encrypted memo; a third-party
	// observer never learns the input blindings, so this does not weaken the
	// settle-vs-refund indistinguishability. A distinct domain per output slot
	// keeps the three blindings independent (no cross-note linkage or collision).
	api.AssertIsEqual(c.RecipientOut.Blinding,
		DeriveOutputBlinding(api, c.OrderIn.Blinding, c.ReservationIn.Blinding, RecipientBlindingDomain))
	api.AssertIsEqual(c.MakerCounter.Blinding,
		DeriveOutputBlinding(api, c.OrderIn.Blinding, c.ReservationIn.Blinding, MakerCounterBlindingDomain))
	api.AssertIsEqual(c.MakerSource.Blinding,
		DeriveOutputBlinding(api, c.OrderIn.Blinding, c.ReservationIn.Blinding, MakerSourceBlindingDomain))

	privateTxHashInputs{
		OrderInputUtxoHash:         orderInHash,
		ReservationInputUtxoHash:   reservationInHash,
		RecipientOutputUtxoHash:    recipientOutHash,
		MakerCounterOutputUtxoHash: makerCounterHash,
		MakerSourceOutputUtxoHash:  makerSourceHash,
		ExternalDataHash:           c.ExternalDataHash,
		PrivateTxHash:              c.Public.PrivateTxHash,
	}.Check(api)

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
}

func (p PublicInputs) Check(api frontend.API, orderInHash, reservationInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	api.AssertIsEqual(p.ReservationInHash, reservationInHash)
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.OrderInHash,
		p.ReservationInHash,
		p.AuthorityOwnerHash,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash         frontend.Variable
	ReservationInputUtxoHash   frontend.Variable
	RecipientOutputUtxoHash    frontend.Variable
	MakerCounterOutputUtxoHash frontend.Variable
	MakerSourceOutputUtxoHash  frontend.Variable
	ExternalDataHash           frontend.Variable
	PrivateTxHash              frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 2-in/3-out; output order (recipient, maker_counter, maker_source) must match
	// the native program's output indices and the SDK.
	inputHashes := []frontend.Variable{
		t.OrderInputUtxoHash,
		t.ReservationInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.RecipientOutputUtxoHash,
		t.MakerCounterOutputUtxoHash,
		t.MakerSourceOutputUtxoHash,
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
	api.AssertIsEqual(c.OrderIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return spp.UtxoHashCircuit(api, c.OrderIn)
}

func (c *Circuit) checkReservationInputUtxo(api frontend.API, reserved frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.ReservationIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.ReservationIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.ReservationIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.ReservationIn.Amount, reserved)
	return spp.UtxoHashCircuit(api, c.ReservationIn)
}

func (c *Circuit) checkRecipientOutputUtxo(api frontend.API, amount, asset frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.RecipientOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RecipientOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.RecipientOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, asset)
	api.AssertIsEqual(c.RecipientOut.Amount, amount)
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return spp.UtxoHashCircuit(api, c.RecipientOut)
}

// checkMakerCounterOutputUtxo is the maker's counter-asset leg: the unspent
// reservation (remainder) returned to the maker's own note. It replaces the old
// pool output -- there is no pool UTXO, so the amount is exactly `remainder`, not
// pool_in + remainder. Asset is the reservation's (destination) asset.
func (c *Circuit) checkMakerCounterOutputUtxo(api frontend.API, remainder frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.MakerCounter.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerCounter.ZoneDataHash, 0)
	api.AssertIsEqual(c.MakerCounter.ZoneProgramID, 0)
	api.AssertIsEqual(c.MakerCounter.DataHash, 0)
	api.AssertIsEqual(c.MakerCounter.Asset, c.ReservationIn.Asset)
	api.AssertIsEqual(c.MakerCounter.Owner, c.Public.AuthorityOwnerHash)

	api.AssertIsEqual(c.MakerCounter.Amount, remainder)
	api.ToBinary(c.MakerCounter.Amount, 64)

	return spp.UtxoHashCircuit(api, c.MakerCounter)
}

// checkMakerSourceOutputUtxo is the pair authority's (maker's) own shielded UTXO
// receiving the settled source asset on a settle outcome. On a refund outcome
// `amount` is 0: the output is still produced (so the shape never differs between
// outcomes) but carries no value.
func (c *Circuit) checkMakerSourceOutputUtxo(api frontend.API, amount frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.MakerSource.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerSource.ZoneDataHash, 0)
	api.AssertIsEqual(c.MakerSource.ZoneProgramID, 0)
	api.AssertIsEqual(c.MakerSource.DataHash, 0)
	api.AssertIsEqual(c.MakerSource.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.MakerSource.Amount, amount)
	api.AssertIsEqual(c.MakerSource.Owner, c.Public.AuthorityOwnerHash)
	return spp.UtxoHashCircuit(api, c.MakerSource)
}

// DeriveOutputBlinding folds both escrow input blindings and a per-slot domain
// into a single 31-byte blinding. Truncating the 254-bit Poseidon output to its
// low 248 bits mirrors the Rust helper, which keeps bytes [1..32] of the hash.
func DeriveOutputBlinding(api frontend.API, orderBlinding, reservationBlinding frontend.Variable, domain uint64) frontend.Variable {
	full := gadget.PoseidonHash(api, []frontend.Variable{
		orderBlinding,
		reservationBlinding,
		frontend.Variable(domain),
	})
	bits := api.ToBinary(full, 254)
	return api.FromBinary(bits[:settleBlindingBits]...)
}
