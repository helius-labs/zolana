package escrow_refund

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit returns an expired order without reading or rewriting maker liquidity.
type Circuit struct {
	Public PublicInputs

	OrderIn      spp.UtxoCircuitFields
	RecipientOut spp.UtxoCircuitFields

	MaxPrice           frontend.Variable
	RecipientOwnerHash frontend.Variable
	CreatedAt          frontend.Variable
	ExpiresAt          frontend.Variable
	ExternalDataHash   frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.OrderIn.DataHash, gadget.PoseidonHash(api, []frontend.Variable{
		c.RecipientOwnerHash,
		c.MaxPrice,
		c.CreatedAt,
		c.ExpiresAt,
		c.Public.ExecutionPrice,
		c.Public.QuoteVersion,
	}))
	orderHash := c.checkOrderInput(api)
	recipientHash := c.checkRecipientOutput(api)
	privateTxHash := spp.PrivateTxHashCircuit(
		api,
		[]frontend.Variable{orderHash},
		[]frontend.Variable{recipientHash},
		[]frontend.Variable{0},
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)
	c.Public.Check(api, orderHash)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	PrivateTxHash   frontend.Variable
	ExecutionPrice  frontend.Variable
	QuoteVersion    frontend.Variable
	OrderInHash     frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderHash)
	api.AssertIsEqual(p.PublicInputHash, gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.QuoteVersion,
		p.OrderInHash,
	}))
}

func (c *Circuit) checkOrderInput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderIn.ZoneProgramID, 0)
	return spp.UtxoHashCircuit(api, c.OrderIn)
}

func (c *Circuit) checkRecipientOutput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.RecipientOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RecipientOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.RecipientOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.RecipientOut.Amount, c.OrderIn.Amount)
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return spp.UtxoHashCircuit(api, c.RecipientOut)
}
