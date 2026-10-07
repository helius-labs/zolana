package verifiableencryption

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

const (
	UncompressedPointBytes = 65
	ScalarBytes            = 32
	maxTagBytes            = 31
)

type Envelope struct {
	SecretTag   []byte
	KdfInfo     []byte
	EphemeralSk [ScalarBytes]frontend.Variable
	RecipientPk [UncompressedPointBytes]frontend.Variable
	Plaintext   []frontend.Variable
}

type Sealed struct {
	RecipientLo  frontend.Variable
	RecipientHi  frontend.Variable
	EphemeralLo  frontend.Variable
	EphemeralHi  frontend.Variable
	SharedSecret frontend.Variable
	Ciphertext   []frontend.Variable
}

func SecretTagValue(tag []byte) *big.Int {
	if len(tag) > maxTagBytes {
		panic(fmt.Sprintf("ecies: secret tag of %d bytes, at most %d", len(tag), maxTagBytes))
	}
	return new(big.Int).SetBytes(tag)
}

func (e Envelope) Seal(api frontend.API) Sealed {
	agreement := p256.AgreeKey(api, e.EphemeralSk, e.RecipientPk)
	sharedSecret := gadget.PoseidonHash(api, []frontend.Variable{
		SecretTagValue(e.SecretTag),
		agreement.SharedLo, agreement.SharedHi,
		agreement.EphemeralLo, agreement.EphemeralHi,
		agreement.RecipientLo, agreement.RecipientHi,
	})

	key, nonce := KeySchedule(api, sharedSecret, e.KdfInfo)
	ciphertext := aes.CTREncrypt(api, key, nonce, e.Plaintext)

	return Sealed{
		RecipientLo:  agreement.RecipientLo,
		RecipientHi:  agreement.RecipientHi,
		EphemeralLo:  agreement.EphemeralLo,
		EphemeralHi:  agreement.EphemeralHi,
		SharedSecret: sharedSecret,
		Ciphertext:   ciphertext,
	}
}
