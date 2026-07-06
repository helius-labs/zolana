package create

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"

	"circuits/orderterms"
)

type Circuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	SourceAssetId frontend.Variable

	SourceAsset frontend.Variable
	EscrowOwner frontend.Variable

	SourceAmount   frontend.Variable
	EscrowBlinding frontend.Variable

	DestinationAsset  frontend.Variable
	DestinationAmount frontend.Variable
	MakerOwnerHash    frontend.Variable
	MakerViewingPk    [33]frontend.Variable
	Expiry            frontend.Variable
	TakerPkFe         frontend.Variable
	FillMode          frontend.Variable

	ExternalDataHash frontend.Variable
	SourceInputHash  frontend.Variable
	ChangeAmount     frontend.Variable
	ChangeBlinding   frontend.Variable
	MarkerOutputHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	makerAddressFe := orderterms.MakerAddressFE(api, c.MakerOwnerHash, c.MakerViewingPk)

	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		c.DestinationAsset,
		c.DestinationAmount,
		makerAddressFe,
		c.Expiry,
		c.TakerPkFe,
		c.FillMode,
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

	change := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.MakerOwnerHash,
		Asset:         c.SourceAsset,
		Amount:        c.ChangeAmount,
		Blinding:      c.ChangeBlinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	changeHash := spp.UtxoHashCircuit(api, change)
	changeHashFinal := api.Select(api.IsZero(c.ChangeAmount), frontend.Variable(0), changeHash)

	api.AssertIsDifferent(c.SourceAmount, 0)
	api.AssertIsDifferent(c.DestinationAmount, 0)

	inputHashes := []frontend.Variable{c.SourceInputHash, frontend.Variable(0)}
	outputHashes := []frontend.Variable{changeHashFinal, escrowHash, c.MarkerOutputHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, c.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{c.PrivateTxHash, c.SourceAssetId, makerAddressFe})
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}
