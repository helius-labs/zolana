package cancel

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
)

type Circuit struct {
	Public PublicInputs

	Order orderterms.OrderTerms

	OrderUtxo    spp.UtxoCircuitFields
	SourceOutput spp.UtxoCircuitFields

	MakerOwnerPkField frontend.Variable
	MakerNullifierPk  frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	makerAddressFe := c.Order.MakerAddressFE(api)

	orderInputUtxoHash := c.checkOrderInputUtxo(api, makerAddressFe)
	sourceOutputUtxoHash := c.checkSourceOutputUtxo(api)
	c.checkMakerAuthorization(api)

	privateTxHashInputs{
		OrderInputUtxoHash:   orderInputUtxoHash,
		SourceOutputUtxoHash: sourceOutputUtxoHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, c.Order.Expiry, c.MakerOwnerPkField)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, expiry frontend.Variable, makerOwnerPkField frontend.Variable) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{p.PrivateTxHash, expiry, makerOwnerPkField})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash   frontend.Variable
	SourceOutputUtxoHash frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.OrderInputUtxoHash}
	outputHashes := []frontend.Variable{t.SourceOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkOrderInputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.OrderUtxo.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.OrderUtxo.ZoneDataHash, 0)
	api.AssertIsEqual(c.OrderUtxo.ZoneProgramID, 0)
	api.AssertIsEqual(c.OrderUtxo.DataHash, c.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(c.OrderUtxo.Amount, 0)
	return spp.UtxoHashCircuit(api, c.OrderUtxo)
}

func (c *Circuit) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.SourceOutput.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.SourceOutput.ZoneDataHash, 0)
	api.AssertIsEqual(c.SourceOutput.ZoneProgramID, 0)
	api.AssertIsEqual(c.SourceOutput.DataHash, 0)
	api.AssertIsEqual(c.SourceOutput.Asset, c.OrderUtxo.Asset)
	api.AssertIsEqual(c.SourceOutput.Amount, c.OrderUtxo.Amount)
	api.AssertIsEqual(c.SourceOutput.Owner, c.Order.MakerOwnerHash)
	return spp.UtxoHashCircuit(api, c.SourceOutput)
}

func (c *Circuit) checkMakerAuthorization(api frontend.API) {
	recomputedOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{c.MakerOwnerPkField, c.MakerNullifierPk})
	api.AssertIsEqual(recomputedOwnerHash, c.Order.MakerOwnerHash)
}
