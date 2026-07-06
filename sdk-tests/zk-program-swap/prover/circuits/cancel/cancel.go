package cancel

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"

	"circuits/orderterms"
)

// TODO: refactor to take structs as input, publicInputs struct, orderUtxo struct, ownerUtxo struct
type Circuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	Expiry        frontend.Variable

	SourceAsset    frontend.Variable
	EscrowOwner    frontend.Variable
	SourceAmount   frontend.Variable
	EscrowBlinding frontend.Variable

	DestinationAsset  frontend.Variable
	DestinationAmount frontend.Variable
	MakerOwnerHash    frontend.Variable
	MakerOwnerPkField frontend.Variable
	MakerNullifierPk  frontend.Variable
	MakerViewingPk    [33]frontend.Variable
	TakerPkFe         frontend.Variable
	FillMode          frontend.Variable

	SourceOutputBlinding frontend.Variable
	ExternalDataHash     frontend.Variable
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

	sourceOutput := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.MakerOwnerHash,
		Asset:         c.SourceAsset,
		Amount:        c.SourceAmount,
		Blinding:      c.SourceOutputBlinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  frontend.Variable(0),
		ZoneProgramID: frontend.Variable(0),
	}
	sourceOutputHash := spp.UtxoHashCircuit(api, sourceOutput)

	api.AssertIsDifferent(c.SourceAmount, 0)

	recomputedOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{c.MakerOwnerPkField, c.MakerNullifierPk})
	api.AssertIsEqual(recomputedOwnerHash, c.MakerOwnerHash)

	inputHashes := []frontend.Variable{escrowHash}
	outputHashes := []frontend.Variable{sourceOutputHash}
	addressHashes := []frontend.Variable{frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, c.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{c.PrivateTxHash, c.Expiry, c.MakerOwnerPkField})
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}
