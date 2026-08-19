package escrow_settle

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Per-output-slot domains folded into DeriveOutputBlinding so the three settle
// outputs derive independent blindings. These constants MUST stay in sync with
// dynamic-swap-prover's Rust copies.
const (
	RecipientBlindingDomain     uint64 = 0x53544C5245434950 // "STLRECIP"
	FunderChangeBlindingDomain  uint64 = 0x53544C464E434847 // "STLFNCHG"
	FunderReceiptBlindingDomain uint64 = 0x53544C464E524350 // "STLFNRCP"
)

// settleBlindingBits truncates the Poseidon output to a 31-byte blinding (the
// SPP Blinding width), matching the Rust derivation's [1..32] byte slice.
const settleBlindingBits = 248

// Circuit fills one escrow. An escrow can only exist at an acceptable price
// (create_escrow rejects execution_price > max_price in the program), so there
// is no refund branch: settle always settles, and the only alternative outcome
// is the separate escrow_cancel circuit after expiry.
//
// 2-in (order, funder's funding note) / 3-out (recipient payout, funder change,
// funder source-asset receipt), the exact IN2_OUT3 shape. The maker's liquidity
// enters here, at settle time, as an ordinary shielded note: there is no shared
// pool and no per-order reservation. The outputs are funder-bound (change and
// receipt go to MakerFunding.Owner), so whoever holds the order UTXO data and
// funds the payout fills the order -- the maker in practice, though the taker
// can self-fill to exit early.
type Circuit struct {
	Public PublicInputs

	OrderIn      spp.UtxoCircuitFields
	MakerFunding spp.UtxoCircuitFields

	RecipientOut  spp.UtxoCircuitFields
	FunderChange  spp.UtxoCircuitFields
	FunderReceipt spp.UtxoCircuitFields

	OrderAmount frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	orderInHash := c.checkOrderInputUtxo(api)
	makerFundingHash := c.checkMakerFundingInputUtxo(api)

	// Every escrow is priced at creation, so ExecutionPrice is always nonzero;
	// assert it so an uncommitted order can never be proven.
	api.AssertIsDifferent(c.Public.ExecutionPrice, 0)

	// owed = OrderAmount * ExecutionPrice. Both factors are 64-bit (OrderAmount
	// via the spent order leaf, ExecutionPrice via the program-fed public
	// input), but their product is a free 128-bit value in the field -- pin it
	// to 64 bits so the funder-change subtraction below cannot be satisfied
	// with a wrapped amount.
	owed := api.Mul(c.OrderAmount, c.Public.ExecutionPrice)
	api.ToBinary(owed, 64)

	recipientOutHash := c.checkRecipientOutputUtxo(api, owed)
	funderChangeHash := c.checkFunderChangeOutputUtxo(api, owed)
	funderReceiptHash := c.checkFunderReceiptOutputUtxo(api)

	// Output blindings are deterministically derived so both parties can find
	// their notes without an encrypted memo: the recipient's from the order
	// blinding alone (the taker knows it and precomputes its payout note at
	// creation -- owed is fixed by the stored execution_price); the funder's
	// two from the funding blinding it picked. A distinct domain per output
	// slot keeps the blindings independent.
	api.AssertIsEqual(c.RecipientOut.Blinding,
		DeriveOutputBlinding(api, c.OrderIn.Blinding, RecipientBlindingDomain))
	api.AssertIsEqual(c.FunderChange.Blinding,
		DeriveOutputBlinding(api, c.MakerFunding.Blinding, FunderChangeBlindingDomain))
	api.AssertIsEqual(c.FunderReceipt.Blinding,
		DeriveOutputBlinding(api, c.MakerFunding.Blinding, FunderReceiptBlindingDomain))

	privateTxHashInputs{
		OrderInputUtxoHash:          orderInHash,
		MakerFundingInputUtxoHash:   makerFundingHash,
		RecipientOutputUtxoHash:     recipientOutHash,
		FunderChangeOutputUtxoHash:  funderChangeHash,
		FunderReceiptOutputUtxoHash: funderReceiptHash,
		ExternalDataHash:            c.ExternalDataHash,
		PrivateTxHash:               c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, orderInHash)
	return nil
}

// PublicInputs folds PrivateTxHash, ExecutionPrice (the escrow's stored public
// price), OrderInHash (the witnessed order UTXO's own reconstructed hash,
// asserted equal in Check below), and DestinationAsset (fed on-chain from
// Pair.destination_asset). The recipient owner-hash is deliberately NOT here --
// it is re-opened from OrderIn.DataHash, which the public OrderInHash pins, so
// the payout destination is enforced without ever being revealed on-chain. The
// native program recomputes this hash from on-chain state
// (`Escrow.execution_price`, `Escrow.order_utxo_hash`,
// `Pair.destination_asset`).
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash    frontend.Variable
	ExecutionPrice   frontend.Variable
	OrderInHash      frontend.Variable
	DestinationAsset frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderInHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderInHash)
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.OrderInHash,
		p.DestinationAsset,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash          frontend.Variable
	MakerFundingInputUtxoHash   frontend.Variable
	RecipientOutputUtxoHash     frontend.Variable
	FunderChangeOutputUtxoHash  frontend.Variable
	FunderReceiptOutputUtxoHash frontend.Variable
	ExternalDataHash            frontend.Variable
	PrivateTxHash               frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// 2-in/3-out; output order (recipient, funder_change, funder_receipt) must
	// match the native program's output indices and the SDK.
	inputHashes := []frontend.Variable{
		t.OrderInputUtxoHash,
		t.MakerFundingInputUtxoHash,
	}
	outputHashes := []frontend.Variable{
		t.RecipientOutputUtxoHash,
		t.FunderChangeOutputUtxoHash,
		t.FunderReceiptOutputUtxoHash,
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

func (c *Circuit) checkMakerFundingInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.MakerFunding.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.MakerFunding.RingDataHash, 0)
	api.AssertIsEqual(c.MakerFunding.RingProgramID, 0)
	api.AssertIsEqual(c.MakerFunding.DataHash, 0)
	// Bind the funding asset to the pair's destination asset so the funder
	// cannot pay the taker in a worthless token.
	api.AssertIsEqual(c.MakerFunding.Asset, c.Public.DestinationAsset)
	return spp.UtxoHashCircuit(api, c.MakerFunding)
}

// checkRecipientOutputUtxo pays `owed` of the destination asset to the
// recipient committed as OrderIn.DataHash (the taker's owner-hash escrow_open
// wrote there, pinned by the public OrderInHash), so the payout destination is
// enforced without being revealed.
func (c *Circuit) checkRecipientOutputUtxo(api frontend.API, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.RecipientOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RecipientOut.RingDataHash, 0)
	api.AssertIsEqual(c.RecipientOut.RingProgramID, 0)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, c.MakerFunding.Asset)
	api.AssertIsEqual(c.RecipientOut.Amount, owed)
	api.AssertIsEqual(c.RecipientOut.Owner, c.OrderIn.DataHash)
	return spp.UtxoHashCircuit(api, c.RecipientOut)
}

// checkFunderChangeOutputUtxo returns the unspent funding (funding - owed) to
// the funder's own note -- same asset and owner as MakerFunding. The 64-bit
// range check rejects underfunding (funding < owed would wrap the field
// subtraction).
func (c *Circuit) checkFunderChangeOutputUtxo(api frontend.API, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.FunderChange.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.FunderChange.RingDataHash, 0)
	api.AssertIsEqual(c.FunderChange.RingProgramID, 0)
	api.AssertIsEqual(c.FunderChange.DataHash, 0)
	api.AssertIsEqual(c.FunderChange.Asset, c.MakerFunding.Asset)
	api.AssertIsEqual(c.FunderChange.Owner, c.MakerFunding.Owner)

	api.AssertIsEqual(c.FunderChange.Amount, api.Sub(c.MakerFunding.Amount, owed))
	api.ToBinary(c.FunderChange.Amount, 64)

	return spp.UtxoHashCircuit(api, c.FunderChange)
}

// checkFunderReceiptOutputUtxo is the funder's own shielded UTXO receiving the
// settled source asset (the full order amount).
func (c *Circuit) checkFunderReceiptOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.FunderReceipt.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.FunderReceipt.RingDataHash, 0)
	api.AssertIsEqual(c.FunderReceipt.RingProgramID, 0)
	api.AssertIsEqual(c.FunderReceipt.DataHash, 0)
	api.AssertIsEqual(c.FunderReceipt.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.FunderReceipt.Amount, c.OrderAmount)
	api.AssertIsEqual(c.FunderReceipt.Owner, c.MakerFunding.Owner)
	return spp.UtxoHashCircuit(api, c.FunderReceipt)
}

// DeriveOutputBlinding folds one input blinding and a per-slot domain into a
// single 31-byte blinding. Truncating the 254-bit Poseidon output to its low
// 248 bits mirrors the Rust helper, which keeps bytes [1..32] of the hash.
func DeriveOutputBlinding(api frontend.API, blinding frontend.Variable, domain uint64) frontend.Variable {
	full := gadget.PoseidonHash(api, []frontend.Variable{
		blinding,
		frontend.Variable(domain),
	})
	bits := api.ToBinary(full, 254)
	return api.FromBinary(bits[:settleBlindingBits]...)
}
