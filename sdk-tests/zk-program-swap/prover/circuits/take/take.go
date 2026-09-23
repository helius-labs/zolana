package take

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

const blindingSeedDomain = 0x53575458 // SWTX; matches the SDK's take_blinding_seed.

type Circuit struct {
	Public PublicInputs

	Core Core
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Core.Order.TakeMode, orderterms.TakeModeDerived)
	// Both parties hold the order opening. Binding the root seed and the published
	// first nullifier makes every payout recoverable without the taker's ciphertext.
	blindingSeed := gnarksdk.Poseidon(api, blindingSeedDomain, c.Core.OrderUtxo.Blinding)
	gnarksdk.AssertTransactionBlindings(
		api,
		c.Public.FirstNullifier,
		blindingSeed,
		c.Core.PrivateTxBlinding,
		c.Core.SourceOutput.Blinding,
		c.Core.DestinationOutput.Blinding,
	)

	c.Core.Check(api, c.Public.PrivateTxHash)

	c.Public.Check(api, c.Core.Order.Expiry)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash  frontend.Variable
	FirstNullifier frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, expiry frontend.Variable) {
	publicInputHash := gnarksdk.Poseidon(api, p.PrivateTxHash, expiry, p.FirstNullifier)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type Core struct {
	Order orderterms.OrderTerms

	OrderUtxo         gnarksdk.Utxo
	TakerIn           gnarksdk.Utxo
	SourceOutput      gnarksdk.Utxo
	DestinationOutput gnarksdk.Utxo

	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (f Core) Check(api frontend.API, privateTxHash frontend.Variable) {
	f.Order.Check(api)
	makerAddressFe := f.Order.MakerAddressFE(api)

	orderInputUtxoHash := f.checkOrderInputUtxo(api, makerAddressFe)
	takerInputUtxoHash := f.checkTakerInputUtxo(api)
	sourceOutputUtxoHash := f.checkSourceOutputUtxo(api)
	destinationOutputUtxoHash := f.checkDestinationOutputUtxo(api)

	recomputedPrivateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{orderInputUtxoHash, takerInputUtxoHash},
		[]frontend.Variable{sourceOutputUtxoHash, destinationOutputUtxoHash},
		f.ExternalDataHash,
		f.PrivateTxBlinding,
	)
	api.AssertIsEqual(recomputedPrivateTxHash, privateTxHash)
}

func (f Core) checkOrderInputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	f.OrderUtxo.AssertDefaultRing(api)
	api.AssertIsEqual(f.OrderUtxo.DataHash, f.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(f.OrderUtxo.Amount, 0)
	return f.OrderUtxo.Hash(api)
}

func (f Core) checkTakerInputUtxo(api frontend.API) frontend.Variable {
	f.TakerIn.AssertDefaultRing(api)
	api.AssertIsEqual(f.TakerIn.DataHash, 0)
	api.AssertIsEqual(f.TakerIn.Asset, f.Order.DestinationAsset)
	api.AssertIsEqual(f.TakerIn.Amount, f.Order.DestinationAmount)
	return f.TakerIn.Hash(api)
}

func (f Core) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	f.SourceOutput.AssertDefaultRing(api)
	api.AssertIsEqual(f.SourceOutput.DataHash, 0)
	api.AssertIsEqual(f.SourceOutput.Asset, f.OrderUtxo.Asset)
	api.AssertIsEqual(f.SourceOutput.Amount, f.OrderUtxo.Amount)
	api.AssertIsEqual(f.SourceOutput.Owner, f.TakerIn.Owner)
	return f.SourceOutput.Hash(api)
}

func (f Core) checkDestinationOutputUtxo(api frontend.API) frontend.Variable {
	f.DestinationOutput.AssertDefaultRing(api)
	api.AssertIsEqual(f.DestinationOutput.DataHash, 0)
	api.AssertIsEqual(f.DestinationOutput.Asset, f.Order.DestinationAsset)
	api.AssertIsEqual(f.DestinationOutput.Amount, f.Order.DestinationAmount)
	api.AssertIsEqual(f.DestinationOutput.Owner, f.Order.MakerOwnerHash)
	return f.DestinationOutput.Hash(api)
}
