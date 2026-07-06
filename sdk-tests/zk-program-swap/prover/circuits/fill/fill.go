package fill

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"

	"circuits/orderterms"
)

const DestinationBlindingDomain uint64 = 0x46494C4C44455256

const destinationBlindingBits = 248

type Circuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	Expiry        frontend.Variable

	SourceAsset       frontend.Variable
	DestinationAsset  frontend.Variable
	EscrowOwner       frontend.Variable
	SourceAmount      frontend.Variable
	EscrowBlinding    frontend.Variable
	DestinationAmount frontend.Variable
	MakerOwnerHash    frontend.Variable
	MakerViewingPk    [33]frontend.Variable
	TakerPkFe         frontend.Variable

	TakerAddress         frontend.Variable
	TakerInBlinding      frontend.Variable
	SourceOutputBlinding frontend.Variable

	ExternalDataHash frontend.Variable
}

func DeriveDestinationBlinding(api frontend.API, escrowBlinding frontend.Variable) frontend.Variable {
	full := gadget.PoseidonHash(api, []frontend.Variable{
		escrowBlinding,
		frontend.Variable(DestinationBlindingDomain),
	})
	bits := api.ToBinary(full, 254)
	return api.FromBinary(bits[:destinationBlindingBits]...)
}

func (c *Circuit) Define(api frontend.API) error {
	makerAddressFe := orderterms.MakerAddressFE(api, c.MakerOwnerHash, c.MakerViewingPk)

	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		c.DestinationAsset,
		c.DestinationAmount,
		makerAddressFe,
		c.Expiry,
		c.TakerPkFe,
		frontend.Variable(orderterms.FillModeDerived),
	})

	escrow := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.EscrowOwner,
		Asset:         c.SourceAsset,
		Amount:        c.SourceAmount,
		Blinding:      c.EscrowBlinding,
		DataHash:      dataHash,
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	escrowHash := spp.UtxoHashCircuit(api, escrow)

	takerUtxo := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.TakerAddress,
		Asset:         c.DestinationAsset,
		Amount:        c.DestinationAmount,
		Blinding:      c.TakerInBlinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	takerUtxoHash := spp.UtxoHashCircuit(api, takerUtxo)

	destinationOutputBlinding := DeriveDestinationBlinding(api, c.EscrowBlinding)

	destinationOutput := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.MakerOwnerHash,
		Asset:         c.DestinationAsset,
		Amount:        c.DestinationAmount,
		Blinding:      destinationOutputBlinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	destinationOutputHash := spp.UtxoHashCircuit(api, destinationOutput)

	sourceOutput := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.TakerAddress,
		Asset:         c.SourceAsset,
		Amount:        c.SourceAmount,
		Blinding:      c.SourceOutputBlinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	sourceOutputHash := spp.UtxoHashCircuit(api, sourceOutput)

	api.AssertIsDifferent(c.SourceAmount, 0)
	api.AssertIsDifferent(c.DestinationAmount, 0)

	inputHashes := []frontend.Variable{escrowHash, takerUtxoHash}
	outputHashes := []frontend.Variable{sourceOutputHash, destinationOutputHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, c.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{c.PrivateTxHash, c.Expiry})
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}
