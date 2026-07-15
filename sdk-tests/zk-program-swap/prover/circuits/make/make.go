package make

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	spp "zolana/prover/circuits/spp_transaction"
)

type Circuit struct {
	PrivateTxHash frontend.Variable `gnark:",public"`

	Order orderterms.OrderTerms

	OrderUtxo spp.UtxoCircuitFields
	Change    spp.UtxoCircuitFields

	SourceInputHash  frontend.Variable
	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	c.Order.Check(api)
	makerAddressFe := c.Order.MakerAddressFE(api)

	orderOutputUtxoHash := c.checkOrderOutputUtxo(api, makerAddressFe)
	changeOutputUtxoHash := c.checkChangeOutputUtxo(api)

	privateTxHashInputs{
		SourceInputHash:      c.SourceInputHash,
		ChangeOutputUtxoHash: changeOutputUtxoHash,
		OrderOutputUtxoHash:  orderOutputUtxoHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.PrivateTxHash,
	}.Check(api)

	return nil
}

type privateTxHashInputs struct {
	SourceInputHash      frontend.Variable
	ChangeOutputUtxoHash frontend.Variable
	OrderOutputUtxoHash  frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.SourceInputHash, frontend.Variable(0)}
	outputHashes := []frontend.Variable{t.ChangeOutputUtxoHash, t.OrderOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkOrderOutputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.OrderUtxo.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderUtxo.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderUtxo.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderUtxo.DataHash, c.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(c.OrderUtxo.Amount, 0)
	return spp.UtxoHashCircuit(api, c.OrderUtxo)
}

func (c *Circuit) checkChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.Change.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.Change.ZoneDataHash, 0)
	api.AssertIsEqual(c.Change.ZoneProgramID, 0)
	api.AssertIsEqual(c.Change.DataHash, 0)
	api.AssertIsEqual(c.Change.Asset, c.OrderUtxo.Asset)
	api.AssertIsEqual(c.Change.Owner, c.Order.MakerOwnerHash)
	return spp.UtxoHashCircuit(api, c.Change)
}
