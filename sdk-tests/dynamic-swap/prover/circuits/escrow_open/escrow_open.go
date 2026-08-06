package escrow_open

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

const OrderExpirySeconds = 600

// Circuit opens a fully collateralized order without touching maker liquidity:
// one exact-sized taker input becomes one program-owned order output.
type Circuit struct {
	Public PublicInputs

	SourceIn spp.UtxoCircuitFields
	OrderOut spp.UtxoCircuitFields

	OrderAmount        frontend.Variable
	MaxPrice           frontend.Variable
	RecipientOwnerHash frontend.Variable
	ExternalDataHash   frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.OrderAmount, 0)
	api.ToBinary(c.OrderAmount, 64)
	api.ToBinary(c.MaxPrice, 64)
	api.AssertIsEqual(c.Public.ExpiresAt, api.Add(c.Public.CreatedAt, OrderExpirySeconds))
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.OrderAmount, c.Public.MaxOrderSize), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.Public.ExecutionPrice, c.MaxPrice), 1)

	sourceHash := c.checkSourceInput(api)
	orderHash := c.checkOrderOutput(api)
	privateTxHash := spp.PrivateTxHashCircuit(
		api,
		[]frontend.Variable{sourceHash},
		[]frontend.Variable{orderHash},
		[]frontend.Variable{0},
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)
	c.Public.Check(api)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash            frontend.Variable
	CreatedAt                frontend.Variable
	ExpiresAt                frontend.Variable
	ExecutionPrice           frontend.Variable
	QuoteVersion             frontend.Variable
	MaxOrderSize             frontend.Variable
	EscrowAuthorityOwnerHash frontend.Variable
	SourceAsset              frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	api.AssertIsEqual(p.PublicInputHash, gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.CreatedAt,
		p.ExpiresAt,
		p.ExecutionPrice,
		p.QuoteVersion,
		p.MaxOrderSize,
		p.EscrowAuthorityOwnerHash,
		p.SourceAsset,
	}))
}

func (c *Circuit) checkSourceInput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.SourceIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.SourceIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.SourceIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.SourceIn.DataHash, 0)
	api.AssertIsEqual(c.SourceIn.Asset, c.Public.SourceAsset)
	api.AssertIsEqual(c.SourceIn.Amount, c.OrderAmount)
	return spp.UtxoHashCircuit(api, c.SourceIn)
}

func (c *Circuit) checkOrderOutput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderOut.Owner, c.Public.EscrowAuthorityOwnerHash)
	api.AssertIsEqual(c.OrderOut.Asset, c.SourceIn.Asset)
	api.AssertIsEqual(c.OrderOut.Amount, c.OrderAmount)
	api.AssertIsEqual(c.OrderOut.DataHash, gadget.PoseidonHash(api, []frontend.Variable{
		c.RecipientOwnerHash,
		c.MaxPrice,
		c.Public.CreatedAt,
		c.Public.ExpiresAt,
		c.Public.ExecutionPrice,
		c.Public.QuoteVersion,
	}))
	return spp.UtxoHashCircuit(api, c.OrderOut)
}
