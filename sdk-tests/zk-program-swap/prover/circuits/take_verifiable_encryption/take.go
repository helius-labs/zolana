package take_verifiable_encryption

import (
	"circuits/orderterms"
	"circuits/take"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"
)

var mergeKdfInfo = []byte("TSPP/merge")

type Circuit struct {
	Public PublicInputs

	Core take.Core

	TakerNullifierPk frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Core.Order.TakeMode, orderterms.TakeModeVerifiable)

	takerOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{c.Core.Order.TakerPkFe, c.TakerNullifierPk})
	api.AssertIsEqual(c.Core.TakerIn.Owner, takerOwnerHash)

	c.Core.Check(api, c.Public.PrivateTxHash)

	ctHash := c.checkVerifiableEncryption(api)

	c.Public.Check(api, c.Core.Order.Expiry, ctHash)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, expiry frontend.Variable, ctHash frontend.Variable) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{p.PrivateTxHash, expiry, ctHash})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkVerifiableEncryption(api frontend.API) frontend.Variable {
	sharedSecret := gadget.PoseidonHash(api, []frontend.Variable{
		c.Core.OrderUtxo.Blinding,
		frontend.Variable(orderterms.TakeEncKdfDomain),
	})
	aesGadget := aes.NewAESGadget(api)
	key, nonce := ve.KeySchedule(api, sharedSecret, mergeKdfInfoVars(), len(mergeKdfInfo))

	var plaintext [71]frontend.Variable
	copy(plaintext[0:8], ve.FieldToBytesBE(api, c.Core.Order.DestinationAmount, 8))
	copy(plaintext[8:40], ve.FieldToBytesBE(api, c.Core.Order.DestinationAsset, 32))
	copy(plaintext[40:71], ve.FieldToBytesBE(api, c.Core.DestinationOutput.Blinding, 31))
	ciphertext := aes.CTREncrypt(api, aesGadget, key, nonce, plaintext[:])
	return gadget.PoseidonHash(api, ve.PackBytesBE(api, ciphertext, 16))
}

func mergeKdfInfoVars() []frontend.Variable {
	out := make([]frontend.Variable, len(mergeKdfInfo))
	for i, b := range mergeKdfInfo {
		out[i] = frontend.Variable(b)
	}
	return out
}
