package escrow_settle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit atomically settles one order against the current private pool.
type Circuit struct {
	Public PublicInputs

	OrderIn spp.UtxoCircuitFields
	PoolIn  spp.UtxoCircuitFields

	RecipientOut spp.UtxoCircuitFields
	PoolOut      spp.UtxoCircuitFields
	AuthorityOut spp.UtxoCircuitFields

	OrderAmount        frontend.Variable
	MaxPrice           frontend.Variable
	RecipientOwnerHash frontend.Variable
	CreatedAt          frontend.Variable
	ExpiresAt          frontend.Variable
	ExternalDataHash   frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.OrderAmount, 0)
	api.ToBinary(c.OrderAmount, 64)
	api.ToBinary(c.MaxPrice, 64)
	api.AssertIsEqual(c.OrderIn.DataHash, gadget.PoseidonHash(api, []frontend.Variable{
		c.RecipientOwnerHash,
		c.MaxPrice,
		c.CreatedAt,
		c.ExpiresAt,
		c.Public.ExecutionPrice,
		c.Public.QuoteVersion,
	}))
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.Public.ExecutionPrice, c.MaxPrice), 1)

	orderHash := c.checkOrderInput(api)
	poolHash := c.checkPoolInput(api)
	owed := api.Mul(c.OrderAmount, c.Public.ExecutionPrice)
	recipientHash := c.checkRecipientOutput(api, owed)
	poolOutHash := c.checkPoolOutput(api, owed)
	authorityHash := c.checkAuthorityOutput(api)

	api.AssertIsBoolean(c.Public.RefreshCapacity)
	required := api.Add(
		c.Public.RemainingReservedLiability,
		api.Mul(c.Public.AvailableSlots, c.Public.SlotValue),
	)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, required, c.PoolOut.Amount), 1)
	nextRequired := api.Add(required, c.Public.SlotValue)
	nextFits := cmp.IsLessOrEqual(api, nextRequired, c.PoolOut.Amount)
	api.AssertIsEqual(api.Mul(c.Public.RefreshCapacity, nextFits), 0)

	privateTxHash := spp.PrivateTxHashCircuit(
		api,
		[]frontend.Variable{orderHash, poolHash},
		[]frontend.Variable{recipientHash, poolOutHash, authorityHash},
		[]frontend.Variable{0, 0},
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)
	c.Public.Check(api, orderHash, poolHash)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash              frontend.Variable
	ExecutionPrice             frontend.Variable
	QuoteVersion               frontend.Variable
	OrderInHash                frontend.Variable
	PoolInHash                 frontend.Variable
	AuthorityOwnerHash         frontend.Variable
	DestinationAsset           frontend.Variable
	RemainingReservedLiability frontend.Variable
	SlotValue                  frontend.Variable
	AvailableSlots             frontend.Variable
	RefreshCapacity            frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, orderHash, poolHash frontend.Variable) {
	api.AssertIsEqual(p.OrderInHash, orderHash)
	api.AssertIsEqual(p.PoolInHash, poolHash)
	api.AssertIsEqual(p.PublicInputHash, gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.ExecutionPrice,
		p.QuoteVersion,
		p.OrderInHash,
		p.PoolInHash,
		p.AuthorityOwnerHash,
		p.DestinationAsset,
		p.RemainingReservedLiability,
		p.SlotValue,
		p.AvailableSlots,
		p.RefreshCapacity,
	}))
}

func (c *Circuit) checkOrderInput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.OrderIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderIn.Amount, c.OrderAmount)
	return spp.UtxoHashCircuit(api, c.OrderIn)
}

func (c *Circuit) checkPoolInput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.PoolIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.PoolIn.DataHash, 0)
	api.AssertIsEqual(c.PoolIn.Asset, c.Public.DestinationAsset)
	return spp.UtxoHashCircuit(api, c.PoolIn)
}

func (c *Circuit) checkRecipientOutput(api frontend.API, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.RecipientOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.RecipientOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.RecipientOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.RecipientOut.DataHash, 0)
	api.AssertIsEqual(c.RecipientOut.Asset, c.PoolIn.Asset)
	api.AssertIsEqual(c.RecipientOut.Amount, owed)
	api.AssertIsEqual(c.RecipientOut.Owner, c.RecipientOwnerHash)
	return spp.UtxoHashCircuit(api, c.RecipientOut)
}

func (c *Circuit) checkPoolOutput(api frontend.API, owed frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.PoolOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.PoolOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.PoolOut.DataHash, 0)
	api.AssertIsEqual(c.PoolOut.Asset, c.PoolIn.Asset)
	api.AssertIsEqual(c.PoolOut.Owner, c.PoolIn.Owner)
	api.AssertIsEqual(c.PoolOut.Amount, api.Sub(c.PoolIn.Amount, owed))
	api.ToBinary(c.PoolOut.Amount, 64)
	return spp.UtxoHashCircuit(api, c.PoolOut)
}

func (c *Circuit) checkAuthorityOutput(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.AuthorityOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.AuthorityOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.AuthorityOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.AuthorityOut.DataHash, 0)
	api.AssertIsEqual(c.AuthorityOut.Asset, c.OrderIn.Asset)
	api.AssertIsEqual(c.AuthorityOut.Amount, c.OrderAmount)
	api.AssertIsEqual(c.AuthorityOut.Owner, c.Public.AuthorityOwnerHash)
	return spp.UtxoHashCircuit(api, c.AuthorityOut)
}
