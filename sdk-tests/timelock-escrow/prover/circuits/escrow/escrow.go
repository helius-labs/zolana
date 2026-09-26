package escrow

import (
	"circuits/escrowterms"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type Circuit struct {
	PrivateTxHash frontend.Variable `gnark:",public"`

	Terms escrowterms.EscrowTerms

	EscrowUtxo gnarksdk.Utxo
	Change     gnarksdk.Utxo

	SourceInputHash   frontend.Variable
	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	escrowOutputUtxoHash := c.checkEscrowOutputUtxo(api)
	changeOutputUtxoHash := c.checkChangeOutputUtxo(api)

	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{c.SourceInputHash, 0},
		[]frontend.Variable{changeOutputUtxoHash, escrowOutputUtxoHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)
	return nil
}

func (c *Circuit) checkEscrowOutputUtxo(api frontend.API) frontend.Variable {
	c.EscrowUtxo.AssertDefaultRing(api)
	api.AssertIsEqual(c.EscrowUtxo.DataHash, c.Terms.DataHash(api))
	api.AssertIsDifferent(c.EscrowUtxo.Amount, 0)
	return c.EscrowUtxo.Hash(api)
}

func (c *Circuit) checkChangeOutputUtxo(api frontend.API) frontend.Variable {
	c.Change.AssertDefaultRing(api)
	api.AssertIsEqual(c.Change.DataHash, 0)
	api.AssertIsEqual(c.Change.Asset, c.EscrowUtxo.Asset)
	api.AssertIsEqual(c.Change.Owner, c.Terms.OwnerHash)
	return c.Change.Hash(api)
}
