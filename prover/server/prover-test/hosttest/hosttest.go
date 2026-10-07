package hosttest

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"fmt"
	"math/big"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/poseidon"
)

const infoChunkBytes = 31

type Keys struct {
	RecipientSecret *ecdh.PrivateKey
	EphemeralSecret *ecdh.PrivateKey
}

func DefaultKeys() Keys {
	var recipient, ephemeral [32]byte
	recipient[31] = 0x2b
	ephemeral[0] = 0x0f
	ephemeral[31] = 0x61
	return Keys{RecipientSecret: mustKey(recipient), EphemeralSecret: mustKey(ephemeral)}
}

func mustKey(scalar [32]byte) *ecdh.PrivateKey {
	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		panic(err)
	}
	return key
}

func (k Keys) RecipientUncompressed() [65]byte {
	return [65]byte(k.RecipientSecret.PublicKey().Bytes())
}

func (k Keys) EphemeralScalar() [32]byte {
	return [32]byte(k.EphemeralSecret.Bytes())
}

func (k Keys) RecipientPacked() (lo, hi *big.Int) {
	return PackCompressed(CompressP256(k.RecipientSecret.PublicKey().Bytes()))
}

func (k Keys) EphemeralPacked() (lo, hi *big.Int) {
	return PackCompressed(CompressP256(k.EphemeralSecret.PublicKey().Bytes()))
}

func (k Keys) SharedSecret(tag []byte) *big.Int {
	dh, err := k.EphemeralSecret.ECDH(k.RecipientSecret.PublicKey())
	if err != nil {
		panic(err)
	}
	return k.sharedSecret(tag, [32]byte(dh))
}

func (k Keys) sharedSecret(tag []byte, sharedX [32]byte) *big.Int {
	sharedLo, sharedHi := PackShared(sharedX)
	ephemeralLo, ephemeralHi := k.EphemeralPacked()
	recipientLo, recipientHi := k.RecipientPacked()
	return mustPoseidon(
		ve.SecretTagValue(tag),
		sharedLo, sharedHi,
		ephemeralLo, ephemeralHi,
		recipientLo, recipientHi,
	)
}

func (k Keys) Encrypt(tag, info, plaintext []byte) (ciphertext []byte, sharedSecret *big.Int) {
	sharedSecret = k.SharedSecret(tag)
	key, nonce := KeySchedule(sharedSecret, info)
	return CTR(key, nonce, plaintext), sharedSecret
}

func CompressP256(uncompressed []byte) [33]byte {
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		panic(fmt.Sprintf("compress: expected a 65-byte 0x04 key, got %d bytes", len(uncompressed)))
	}
	var out [33]byte
	out[0] = 2 + (uncompressed[64] & 1)
	copy(out[1:], uncompressed[1:33])
	return out
}

func PackCompressed(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetBytes(key[31:])
}

func PackShared(x [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(x[:31]), new(big.Int).SetBytes(x[31:])
}

func KeySchedule(sharedSecret *big.Int, info []byte) (key [32]byte, nonce [12]byte) {
	siloInputs := []*big.Int{tagValue(ve.DomSepSilo), sharedSecret}
	for offset := 0; offset < len(info); offset += infoChunkBytes {
		siloInputs = append(siloInputs, new(big.Int).SetBytes(info[offset:min(offset+infoChunkBytes, len(info))]))
	}
	siloed := mustPoseidon(siloInputs...)
	keyLo := fieldBytes(mustPoseidon(tagValue(ve.DomSepKey), siloed))
	keyHi := fieldBytes(mustPoseidon(tagValue(ve.DomSepKey+1), siloed))
	nonceRaw := fieldBytes(mustPoseidon(tagValue(ve.DomSepNonce), siloed))
	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
	return key, nonce
}

func CTR(key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	counter[15] = 2
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(out, plaintext)
	return out
}

func tagValue(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func fieldBytes(v *big.Int) [32]byte {
	var out [32]byte
	v.FillBytes(out[:])
	return out
}

func mustPoseidon(inputs ...*big.Int) *big.Int {
	h, err := poseidon.Hash(inputs)
	if err != nil {
		panic(err)
	}
	return h
}
