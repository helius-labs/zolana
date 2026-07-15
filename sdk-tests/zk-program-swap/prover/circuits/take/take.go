package take

import (
	"circuits/orderterms"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
)

const DestinationBlindingDomain uint64 = 0x46494C4C44455256

const destinationBlindingBits = 248

type Circuit struct {
	Public PublicInputs

	Core Core
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Core.Order.TakeMode, orderterms.TakeModeDerived)
	api.AssertIsEqual(c.Core.DestinationOutput.Blinding, DeriveDestinationBlinding(api, c.Core.OrderUtxo.Blinding))

	c.Core.Check(api, c.Public.PrivateTxHash)

	c.Public.Check(api, c.Core.Order.Expiry)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, expiry frontend.Variable) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{p.PrivateTxHash, expiry})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type Core struct {
	Order orderterms.OrderTerms

	OrderUtxo         spp.UtxoCircuitFields
	TakerIn           spp.UtxoCircuitFields
	SourceOutput      spp.UtxoCircuitFields
	DestinationOutput spp.UtxoCircuitFields

	ExternalDataHash frontend.Variable
}

func (f Core) Check(api frontend.API, privateTxHash frontend.Variable) {
	f.Order.Check(api)
	makerAddressFe := f.Order.MakerAddressFE(api)

	orderInputUtxoHash := f.checkOrderInputUtxo(api, makerAddressFe)
	takerInputUtxoHash := f.checkTakerInputUtxo(api)
	sourceOutputUtxoHash := f.checkSourceOutputUtxo(api)
	destinationOutputUtxoHash := f.checkDestinationOutputUtxo(api)

	privateTxHashInputs{
		OrderInputUtxoHash:        orderInputUtxoHash,
		TakerInputUtxoHash:        takerInputUtxoHash,
		SourceOutputUtxoHash:      sourceOutputUtxoHash,
		DestinationOutputUtxoHash: destinationOutputUtxoHash,
		ExternalDataHash:          f.ExternalDataHash,
		PrivateTxHash:             privateTxHash,
	}.Check(api)
}

type privateTxHashInputs struct {
	OrderInputUtxoHash        frontend.Variable
	TakerInputUtxoHash        frontend.Variable
	SourceOutputUtxoHash      frontend.Variable
	DestinationOutputUtxoHash frontend.Variable
	ExternalDataHash          frontend.Variable
	PrivateTxHash             frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.OrderInputUtxoHash, t.TakerInputUtxoHash}
	outputHashes := []frontend.Variable{t.SourceOutputUtxoHash, t.DestinationOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (f Core) checkOrderInputUtxo(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	api.AssertIsEqual(f.OrderUtxo.Domain, spp.UtxoDomain)
	api.AssertIsEqual(f.OrderUtxo.ZoneDataHash, 0)
	api.AssertIsEqual(f.OrderUtxo.ZoneProgramID, 0)
	api.AssertIsEqual(f.OrderUtxo.DataHash, f.Order.DataHash(api, makerAddressFe))
	api.AssertIsDifferent(f.OrderUtxo.Amount, 0)
	return spp.UtxoHashCircuit(api, f.OrderUtxo)
}

func (f Core) checkTakerInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(f.TakerIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(f.TakerIn.ZoneDataHash, 0)
	api.AssertIsEqual(f.TakerIn.ZoneProgramID, 0)
	api.AssertIsEqual(f.TakerIn.DataHash, 0)
	api.AssertIsEqual(f.TakerIn.Asset, f.Order.DestinationAsset)
	api.AssertIsEqual(f.TakerIn.Amount, f.Order.DestinationAmount)
	return spp.UtxoHashCircuit(api, f.TakerIn)
}

func (f Core) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(f.SourceOutput.Domain, spp.UtxoDomain)
	api.AssertIsEqual(f.SourceOutput.ZoneDataHash, 0)
	api.AssertIsEqual(f.SourceOutput.ZoneProgramID, 0)
	api.AssertIsEqual(f.SourceOutput.DataHash, 0)
	api.AssertIsEqual(f.SourceOutput.Asset, f.OrderUtxo.Asset)
	api.AssertIsEqual(f.SourceOutput.Amount, f.OrderUtxo.Amount)
	api.AssertIsEqual(f.SourceOutput.Owner, f.TakerIn.Owner)
	return spp.UtxoHashCircuit(api, f.SourceOutput)
}

func (f Core) checkDestinationOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(f.DestinationOutput.Domain, spp.UtxoDomain)
	api.AssertIsEqual(f.DestinationOutput.ZoneDataHash, 0)
	api.AssertIsEqual(f.DestinationOutput.ZoneProgramID, 0)
	api.AssertIsEqual(f.DestinationOutput.DataHash, 0)
	api.AssertIsEqual(f.DestinationOutput.Asset, f.Order.DestinationAsset)
	api.AssertIsEqual(f.DestinationOutput.Amount, f.Order.DestinationAmount)
	api.AssertIsEqual(f.DestinationOutput.Owner, f.Order.MakerOwnerHash)
	return spp.UtxoHashCircuit(api, f.DestinationOutput)
}

func DeriveDestinationBlinding(api frontend.API, orderUtxoBlinding frontend.Variable) frontend.Variable {
	full := gadget.PoseidonHash(api, []frontend.Variable{
		orderUtxoBlinding,
		frontend.Variable(DestinationBlindingDomain),
	})
	bits := api.ToBinary(full, 254)
	return api.FromBinary(bits[:destinationBlindingBits]...)
}
