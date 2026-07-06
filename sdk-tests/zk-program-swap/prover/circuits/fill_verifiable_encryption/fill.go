package fill_verifiable_encryption

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"

	"circuits/orderterms"
)

var kdfInfo = []byte("TSPP/merge")

type Circuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash      frontend.Variable
	Expiry             frontend.Variable
	SourceAsset        frontend.Variable
	DestinationAsset   frontend.Variable
	EscrowOwner        frontend.Variable
	SourceAmount       frontend.Variable
	EscrowBlinding     frontend.Variable
	DestinationAmount  frontend.Variable
	MakerOwnerHash     frontend.Variable
	MakerViewingPk     [33]frontend.Variable
	TakerPkFe          frontend.Variable
	TakerNullifierPk   frontend.Variable

	TakerAddress              frontend.Variable
	TakerInBlinding           frontend.Variable
	DestinationOutputBlinding frontend.Variable
	SourceOutputBlinding      frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	makerAddressFe := orderterms.MakerAddressFE(api, c.MakerOwnerHash, c.MakerViewingPk)

	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		c.DestinationAsset,
		c.DestinationAmount,
		makerAddressFe,
		c.Expiry,
		c.TakerPkFe,
		frontend.Variable(orderterms.FillModeVerifiable),
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

	takerOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{c.TakerPkFe, c.TakerNullifierPk})
	api.AssertIsEqual(c.TakerAddress, takerOwnerHash)

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

	destinationOutput := spp.UtxoCircuitFields{
		Domain:        frontend.Variable(spp.UtxoDomain),
		Owner:         c.MakerOwnerHash,
		Asset:         c.DestinationAsset,
		Amount:        c.DestinationAmount,
		Blinding:      c.DestinationOutputBlinding,
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

	sharedSecret := gadget.PoseidonHash(api, []frontend.Variable{
		c.EscrowBlinding,
		frontend.Variable(orderterms.FillEncKdfDomain),
	})
	aesGadget := aes.NewAESGadget(api)
	key, nonce := ve.KeySchedule(api, sharedSecret, kdfInfoVars(), len(kdfInfo))

	var plaintext [71]frontend.Variable
	copy(plaintext[0:8], ve.FieldToBytesBE(api, c.DestinationAmount, 8))
	copy(plaintext[8:40], ve.FieldToBytesBE(api, c.DestinationAsset, 32))
	copy(plaintext[40:71], ve.FieldToBytesBE(api, c.DestinationOutputBlinding, 31))
	ciphertext := aes.CTREncrypt(api, aesGadget, key, nonce, plaintext[:])
	ctHash := gadget.PoseidonHash(api, ve.PackBytesBE(api, ciphertext, 16))

	inputHashes := []frontend.Variable{escrowHash, takerUtxoHash}
	outputHashes := []frontend.Variable{sourceOutputHash, destinationOutputHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, c.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{c.PrivateTxHash, c.Expiry, ctHash})
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}

func kdfInfoVars() []frontend.Variable {
	out := make([]frontend.Variable, len(kdfInfo))
	for i, b := range kdfInfo {
		out[i] = frontend.Variable(b)
	}
	return out
}
