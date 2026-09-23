package make

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type Circuit struct {
	PrivateTxHash frontend.Variable `gnark:",public"`

	Order orderterms.OrderTerms

	OrderUtxo gnarksdk.Utxo
	Change    gnarksdk.Utxo

	SourceInputHash   frontend.Variable
	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	c.Order.Check(api)
	makerAddressFe := c.Order.MakerAddressFE(api)

	orderOutputUtxoHash := c.checkOrderOutputUtxo(api, makerAddressFe)
	changeOutputUtxoHash := c.checkChangeOutputUtxo(api)

	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{c.SourceInputHash, 0},
		[]frontend.Variable{changeOutputUtxoHash, orderOutputUtxoHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)
	return nil
}

func (c *Circuit) checkOrderOutputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	c.OrderUtxo.AssertDefaultRing(api)
	api.AssertIsEqual(c.OrderUtxo.DataHash, c.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(c.OrderUtxo.Amount, 0)
	return c.OrderUtxo.Hash(api)
}

func (c *Circuit) checkChangeOutputUtxo(api frontend.API) frontend.Variable {
	c.Change.AssertDefaultRing(api)
	api.AssertIsEqual(c.Change.DataHash, 0)
	api.AssertIsEqual(c.Change.Asset, c.OrderUtxo.Asset)
	api.AssertIsEqual(c.Change.Owner, c.Order.MakerOwnerHash)
	return c.Change.Hash(api)
}
