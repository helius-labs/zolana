package withdraw

import (
	"circuits/escrowterms"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type Circuit struct {
	Public PublicInputs

	Terms escrowterms.EscrowTerms

	EscrowUtxo   gnarksdk.Utxo
	SourceOutput gnarksdk.Utxo

	OwnerPkField frontend.Variable
	NullifierPk  frontend.Variable

	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	escrowInputUtxoHash := c.checkEscrowInputUtxo(api)
	sourceOutputUtxoHash := c.checkSourceOutputUtxo(api)
	c.checkOwnerAuthorization(api)

	privateTxHash := gnarksdk.PrivateTxHash(
		api,
		[]frontend.Variable{escrowInputUtxoHash},
		[]frontend.Variable{sourceOutputUtxoHash},
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	c.Public.Check(api, c.Terms.Unlock, c.OwnerPkField)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, unlock frontend.Variable, ownerPkField frontend.Variable) {
	publicInputHash := gnarksdk.Poseidon(api, p.PrivateTxHash, unlock, ownerPkField)
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkEscrowInputUtxo(api frontend.API) frontend.Variable {
	c.EscrowUtxo.AssertDefaultRing(api)
	api.AssertIsEqual(c.EscrowUtxo.DataHash, c.Terms.DataHash(api))
	api.AssertIsDifferent(c.EscrowUtxo.Amount, 0)
	return c.EscrowUtxo.Hash(api)
}

func (c *Circuit) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	c.SourceOutput.AssertDefaultRing(api)
	api.AssertIsEqual(c.SourceOutput.DataHash, 0)
	api.AssertIsEqual(c.SourceOutput.Asset, c.EscrowUtxo.Asset)
	api.AssertIsEqual(c.SourceOutput.Amount, c.EscrowUtxo.Amount)
	api.AssertIsEqual(c.SourceOutput.Owner, c.Terms.OwnerHash)
	return c.SourceOutput.Hash(api)
}

func (c *Circuit) checkOwnerAuthorization(api frontend.API) {
	recomputedOwnerHash := gnarksdk.Poseidon(api, c.OwnerPkField, c.NullifierPk)
	api.AssertIsEqual(recomputedOwnerHash, c.Terms.OwnerHash)
}
