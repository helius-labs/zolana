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

// Envelope encrypts Plaintext to RecipientPk under a fresh ephemeral key.
// Encrypt binds the raw ECDH output to both public keys that produced it, so
// the AES key schedule input is a single field element that cannot be replayed
// under a different key pair:
//
//	shared_secret = Poseidon(SecretTag,
//	                         dh_lo, dh_hi,
//	                         eph_pk_lo, eph_pk_hi,
//	                         recipient_pk_lo, recipient_pk_hi
//	                         [, Context])
//
// The Rust host derivation MUST mirror this input order element for element.
// Ciphertext integrity is enforced by a Poseidon ciphertext hash folded into
// the public input hash, not by a GCM tag.
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
	keyAgreement := p256.ComputeKeyAgreement(api, e.EphemeralSk, e.RecipientPk)
	sharedSecretPreimage := []frontend.Variable{
		SecretTagValue(e.SecretTag),
		keyAgreement.SharedLo, keyAgreement.SharedHi,
		keyAgreement.EphemeralLo, keyAgreement.EphemeralHi,
		keyAgreement.RecipientLo, keyAgreement.RecipientHi,
	}
	if e.Context != nil {
		sharedSecretPreimage = append(sharedSecretPreimage, e.Context)
	}
	sharedSecret := gadget.PoseidonHash(api, sharedSecretPreimage)

	key, nonce := KeySchedule(api, sharedSecret, e.KdfInfo)
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)

	return Encrypted{
		RecipientLo:  keyAgreement.RecipientLo,
		RecipientHi:  keyAgreement.RecipientHi,
		EphemeralLo:  keyAgreement.EphemeralLo,
		EphemeralHi:  keyAgreement.EphemeralHi,
		SharedSecret: sharedSecret,
		Ciphertext:   ciphertext,
	}
}
