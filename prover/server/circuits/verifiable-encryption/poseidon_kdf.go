package verifiableencryption

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"

	"zolana/prover/circuits/gadget"
)

// Domain separators packed into a field element ("32-bit ASCII tags packed into
// a field element", spec Merge Proof Verifiable encryption). The Rust host KDF
// MUST mirror these byte-for-byte.
const (
	DomSepSilo  uint32 = 0x544d5349 // "TMSI" (key-schedule context / info silo)
	DomSepKey   uint32 = 0x544d534b // "TMSK" (key_sep_0; key_sep_1 = +1 = "TMSL")
	DomSepNonce uint32 = 0x544d534e // "TMSN" (CTR nonce)
)

// FieldToBytesBE decomposes a field element into nbytes big-endian bytes.
func FieldToBytesBE(api frontend.API, v frontend.Variable, nbytes int) []frontend.Variable {
	allBits := bits.ToBinary(api, v, bits.WithNbDigits(nbytes*8))
	out := make([]frontend.Variable, nbytes)
	for i := 0; i < nbytes; i++ {
		start := (nbytes - 1 - i) * 8
		b := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			b = api.Add(b, api.Mul(allBits[start+j], big.NewInt(int64(1<<j))))
		}
		out[i] = b
	}
	return out
}

// feToBytesBE decomposes a field element into 32 big-endian bytes.
// BN254 scalar field is 254 bits, so the top 2 bits (and thus the top 2 bits
// of byte 0) are always zero -- this matches light-poseidon's `to_bytes_be`
// representation in the Rust SDK.
//
// Cost: ~256 bit-decomposition constraints + 32 linear byte combinations.
func feToBytesBE(api frontend.API, fe frontend.Variable) [32]frontend.Variable {
	// 256-bit decomposition; gnark caps at field bit length and pads top with 0.
	allBits := bits.ToBinary(api, fe, bits.WithNbDigits(256))

	var out [32]frontend.Variable
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		// Big-endian: byte 0 is the most significant byte (bits 248..255).
		bytePos := 31 - byteIdx
		startBit := bytePos * 8
		var b frontend.Variable = frontend.Variable(0)
		for j := 0; j < 8; j++ {
			b = api.Add(b, api.Mul(allBits[startBit+j], big.NewInt(int64(1<<j))))
		}
		out[byteIdx] = b
	}
	return out
}

// KeySchedule mirrors sdk-libs/keypair/src/encryption.rs:key_schedule in-circuit.
//
// Inputs:
//   - sharedSecret: a single field element (output of DeriveSharedSecret)
//   - info: variable info bytes; only info[0:infoLen] is consumed
//   - infoLen: compile-time length of the active info prefix (must be <= 62)
//
// Returns (aes256Key, aes-gcm nonce).
//
// 4 Poseidon calls: silo (t=5), keyLo (t=3), keyHi (t=3), nonce (t=3).
// 3 field-element-to-bytes decompositions.
func KeySchedule(
	api frontend.API,
	sharedSecret frontend.Variable,
	info []frontend.Variable,
	infoLen int,
) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	if infoLen > len(info) {
		panic("KeySchedule: infoLen larger than info slice")
	}
	infoFields := gadget.PackBytesBE(api, info[:infoLen])

	// Silo step commits the fixed info through the canonical 31-byte packing.
	siloInputs := []frontend.Variable{
		frontend.Variable(uint64(DomSepSilo)),
		sharedSecret,
	}
	siloInputs = append(siloInputs, infoFields...)
	siloed := gadget.PoseidonHash(api, siloInputs)

	// Two Poseidon calls for the AES-256 key (16 bytes from each output).
	keyLo := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey)),
		siloed,
	})
	keyHi := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey + 1)),
		siloed,
	})

	keyLoBytes := feToBytesBE(api, keyLo)
	keyHiBytes := feToBytesBE(api, keyHi)
	for i := 0; i < 16; i++ {
		key[i] = keyHiBytes[16+i]
		key[16+i] = keyLoBytes[16+i]
	}

	// Single Poseidon call for the GCM nonce (last 12 bytes of the output).
	nonceRaw := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepNonce)),
		siloed,
	})
	nonceBytes := feToBytesBE(api, nonceRaw)
	for i := 0; i < 12; i++ {
		nonce[i] = nonceBytes[20+i]
	}

	return key, nonce
}
