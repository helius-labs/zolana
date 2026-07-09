package create

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
)

type Circuit struct {
	Public PublicInputs

	Order OrderTerms

	Escrow spp.UtxoCircuitFields
	Change spp.UtxoCircuitFields
	Marker spp.UtxoCircuitFields

	SourceInputHash  frontend.Variable
	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	c.Order.Check(api)
	makerAddressFe := c.Order.MakerAddressFE(api)

	escrowOutputUtxoHash := c.checkEscrowOutputUtxo(api, makerAddressFe)
	changeOutputUtxoHash := c.checkChangeOutputUtxo(api)
	markerOutputUtxoHash := c.checkMarkerOutputUtxo(api)

	privateTxHashInputs{
		SourceInputHash:      c.SourceInputHash,
		ChangeOutputUtxoHash: changeOutputUtxoHash,
		EscrowOutputUtxoHash: escrowOutputUtxoHash,
		MarkerOutputUtxoHash: markerOutputUtxoHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, makerAddressFe)
	return nil
}

type OrderTerms struct {
	DestinationAsset  frontend.Variable
	DestinationAmount frontend.Variable
	MakerOwnerHash    frontend.Variable
	MakerViewingPk    [33]frontend.Variable
	Expiry            frontend.Variable
	TakerPkFe         frontend.Variable
	FillMode          frontend.Variable
}

func (o OrderTerms) Check(api frontend.API) {
	api.AssertIsDifferent(o.DestinationAmount, 0)
	api.ToBinary(o.DestinationAmount, 64)
	api.AssertIsBoolean(o.FillMode)
}

func (o OrderTerms) MakerAddressFE(api frontend.API) frontend.Variable {
	return orderterms.MakerAddressFE(api, o.MakerOwnerHash, o.MakerViewingPk)
}

func (o OrderTerms) DataHash(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		o.DestinationAsset,
		o.DestinationAmount,
		makerAddressFe,
		o.Expiry,
		o.TakerPkFe,
		o.FillMode,
	})
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	SourceMint    frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, makerAddressFe frontend.Variable) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{p.PrivateTxHash, p.SourceMint, makerAddressFe})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	SourceInputHash      frontend.Variable
	ChangeOutputUtxoHash frontend.Variable
	EscrowOutputUtxoHash frontend.Variable
	MarkerOutputUtxoHash frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.SourceInputHash, frontend.Variable(0)}
	outputHashes := []frontend.Variable{t.ChangeOutputUtxoHash, t.EscrowOutputUtxoHash, t.MarkerOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkEscrowOutputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	api.AssertIsEqual(c.Escrow.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.Escrow.ZoneDataHash, 0)
	api.AssertIsEqual(c.Escrow.ZoneProgramID, 0)
	api.AssertIsEqual(c.Escrow.DataHash, c.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(c.Escrow.Amount, 0)
	return spp.UtxoHashCircuit(api, c.Escrow)
}

func (c *Circuit) checkChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.Change.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.Change.ZoneDataHash, 0)
	api.AssertIsEqual(c.Change.ZoneProgramID, 0)
	api.AssertIsEqual(c.Change.DataHash, 0)
	api.AssertIsEqual(c.Change.Asset, c.Escrow.Asset)
	api.AssertIsEqual(c.Change.Owner, c.Order.MakerOwnerHash)
	changeHash := spp.UtxoHashCircuit(api, c.Change)
	return api.Select(api.IsZero(c.Change.Amount), frontend.Variable(0), changeHash)
}

func (c *Circuit) checkMarkerOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.Marker.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.Marker.ZoneDataHash, 0)
	api.AssertIsEqual(c.Marker.ZoneProgramID, 0)
	api.AssertIsEqual(c.Marker.DataHash, 0)
	api.AssertIsEqual(c.Marker.Amount, 0)
	solAssetFe := gadget.PoseidonHash(api, []frontend.Variable{0, 0})
	api.AssertIsEqual(c.Marker.Asset, solAssetFe)
	api.AssertIsEqual(c.Marker.Blinding, 0)
	return spp.UtxoHashCircuit(api, c.Marker)
}
