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
	Context     frontend.Variable
}

type Encrypted struct {
	RecipientLo  frontend.Variable
	RecipientHi  frontend.Variable
	EphemeralLo  frontend.Variable
	EphemeralHi  frontend.Variable
	SharedSecret frontend.Variable
	Ciphertext   []frontend.Variable
}

// SecretTagValue encodes a compile-time domain tag as a big-endian integer.
// Tags are at most 31 bytes and must not start with zero; the empty tag encodes
// zero. This gives every accepted tag a unique integer representation.
func SecretTagValue(tag []byte) *big.Int {
	if len(tag) > maxTagBytes {
		panic(fmt.Sprintf("ecies: secret tag of %d bytes, at most %d", len(tag), maxTagBytes))
	}
	if len(tag) > 0 && tag[0] == 0 {
		panic("ecies: secret tag must not start with zero")
	}
	return new(big.Int).SetBytes(tag)
}

func (e Envelope) Encrypt(api frontend.API) Encrypted {
	agreement := p256.AgreeKey(api, e.EphemeralSk, e.RecipientPk)
	secretInputs := []frontend.Variable{
		SecretTagValue(e.SecretTag),
		agreement.SharedLo, agreement.SharedHi,
		agreement.EphemeralLo, agreement.EphemeralHi,
		agreement.RecipientLo, agreement.RecipientHi,
	}
	if e.Context != nil {
		secretInputs = append(secretInputs, e.Context)
	}
	sharedSecret := gadget.PoseidonHash(api, secretInputs)

	key, nonce := KeySchedule(api, sharedSecret, e.KdfInfo)
	ciphertext := aes.CTREncrypt(api, key, nonce, e.Plaintext)

	return Encrypted{
		RecipientLo:  agreement.RecipientLo,
		RecipientHi:  agreement.RecipientHi,
		EphemeralLo:  agreement.EphemeralLo,
		EphemeralHi:  agreement.EphemeralHi,
		SharedSecret: sharedSecret,
		Ciphertext:   ciphertext,
	}
}
