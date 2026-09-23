package cancel

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type Circuit struct {
	Public PublicInputs

	Order orderterms.OrderTerms

	OrderUtxo    gnarksdk.Utxo
	SourceOutput gnarksdk.Utxo

	MakerOwnerPkField frontend.Variable
	MakerNullifierPk  frontend.Variable

	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	makerAddressFe := c.Order.MakerAddressFE(api)

	orderInputUtxoHash := c.checkOrderInputUtxo(api, makerAddressFe)
	sourceOutputUtxoHash := c.checkSourceOutputUtxo(api)
	c.checkMakerAuthorization(api)

	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{orderInputUtxoHash},
		[]frontend.Variable{sourceOutputUtxoHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api, c.Order.Expiry, c.MakerOwnerPkField)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, expiry frontend.Variable, makerOwnerPkField frontend.Variable) {
	publicInputHash := gnarksdk.Poseidon(api, p.PrivateTxHash, expiry, makerOwnerPkField)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	c.OrderUtxo.AssertDefaultRing(api)
	api.AssertIsEqual(c.OrderUtxo.DataHash, c.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(c.OrderUtxo.Amount, 0)
	return c.OrderUtxo.Hash(api)
}

func (c *Circuit) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	c.SourceOutput.AssertDefaultRing(api)
	api.AssertIsEqual(c.SourceOutput.DataHash, 0)
	api.AssertIsEqual(c.SourceOutput.Asset, c.OrderUtxo.Asset)
	api.AssertIsEqual(c.SourceOutput.Amount, c.OrderUtxo.Amount)
	api.AssertIsEqual(c.SourceOutput.Owner, c.Order.MakerOwnerHash)
	return c.SourceOutput.Hash(api)
}

func (c *Circuit) checkMakerAuthorization(api frontend.API) {
	recomputedOwnerHash := gnarksdk.Poseidon(api, c.MakerOwnerPkField, c.MakerNullifierPk)
	api.AssertIsEqual(recomputedOwnerHash, c.Order.MakerOwnerHash)
}
