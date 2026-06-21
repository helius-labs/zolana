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
	DomSepSharedSecret uint32 = 0x544d5353 // "TMSS" (TSPP merge shared secret)
	DomSepSilo         uint32 = 0x544d5349 // "TMSI" (key-schedule context / info silo)
	DomSepKey          uint32 = 0x544d534b // "TMSK" (key_sep_0; key_sep_1 = +1 = "TMSL")
	DomSepNonce        uint32 = 0x544d534e // "TMSN" (CTR nonce)
)

// pack256 builds 256^k as a *big.Int constant for k in 0..31.
func pack256(k int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(8*k))
}

// Pack32To2FECircuit mirrors interface/src/shared.rs:split_32_bytes in-circuit.
//
//	lo = bytes[0..31] left-padded with one zero byte (i.e. lo as big-endian
//	     integer = sum_{i=0..30} bytes[i] * 256^(30-i))
//	hi = bytes[31] (single byte, value < 2^8)
//
// Both packings are linear combinations -- gnark folds them into the next
// nonlinear gate, so the cost is effectively zero R1CS constraints.
func Pack32To2FECircuit(api frontend.API, bytes [32]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for i := 0; i < 31; i++ {
		// position 30-i means byte 0 is the most significant, byte 30 is the least.
		coeff := pack256(30 - i)
		lo = api.Add(lo, api.Mul(bytes[i], coeff))
	}
	hi = bytes[31]
	return lo, hi
}

// Pack33To2FECircuit mirrors interface/src/shared.rs:split_33_bytes in-circuit.
//
//	lo = bytes[0..31] left-padded with one zero byte (same as pack32To2FE)
//	hi = bytes[31]*256 + bytes[32] (16-bit value)
func Pack33To2FECircuit(api frontend.API, bytes [33]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for i := 0; i < 31; i++ {
		coeff := pack256(30 - i)
		lo = api.Add(lo, api.Mul(bytes[i], coeff))
	}
	hi = api.Add(api.Mul(bytes[31], big.NewInt(256)), bytes[32])
	return lo, hi
}

// packInfoTo2FECircuit mirrors interface/src/shared.rs:pack_to_2_fe in-circuit.
// infoLen is a compile-time constant; only the active prefix info[0:infoLen]
// is interpreted, the rest is ignored.
//
// Layout (matching the Rust):
//   - split = min(31, infoLen)
//   - fe0[0] = infoLen (length byte)
//   - fe0[32-split..32] = info[0..split]
//   - fe1[32-(infoLen-split)..32] = info[split..infoLen]
//
// Note: when infoLen <= 30 the length byte at fe0[0] does NOT overlap with
// any data byte. When infoLen == 31 the length byte at fe0[0] occupies the
// position immediately above data, with no gap.
func packInfoTo2FECircuit(api frontend.API, info []frontend.Variable, infoLen int) (lo, hi frontend.Variable) {
	if infoLen > 62 {
		panic("packInfoTo2FECircuit: infoLen exceeds 62")
	}
	if infoLen > len(info) {
		panic("packInfoTo2FECircuit: infoLen larger than info slice")
	}

	split := infoLen
	if split > 31 {
		split = 31
	}

	// fe0 as big-endian 32-byte field element:
	//   byte[0] = infoLen (constant)
	//   bytes[1 .. 32-split] = 0 (gap when infoLen < 31)
	//   bytes[32-split .. 32] = info[0..split]
	// As an integer: lo = infoLen * 256^31 + sum_{i=0..split-1}(info[i] * 256^(split-1-i))
	lo = api.Mul(big.NewInt(int64(infoLen)), pack256(31))
	for i := 0; i < split; i++ {
		coeff := pack256(split - 1 - i)
		lo = api.Add(lo, api.Mul(info[i], coeff))
	}

	remainder := infoLen - split
	hi = frontend.Variable(0)
	for i := 0; i < remainder; i++ {
		coeff := pack256(remainder - 1 - i)
		hi = api.Add(hi, api.Mul(info[split+i], coeff))
	}
	return lo, hi
}

// PackBytesBE packs a byte slice into big-endian field elements of bytesPerFE
// bytes each (the final element holds the remaining bytes).
func PackBytesBE(api frontend.API, bytes []frontend.Variable, bytesPerFE int) []frontend.Variable {
	var fes []frontend.Variable
	for offset := 0; offset < len(bytes); offset += bytesPerFE {
		end := offset + bytesPerFE
		if end > len(bytes) {
			end = len(bytes)
		}
		chunk := bytes[offset:end]
		v := frontend.Variable(0)
		n := len(chunk)
		for i, b := range chunk {
			coeff := new(big.Int).Lsh(big.NewInt(1), uint(8*(n-1-i)))
			v = api.Add(v, api.Mul(b, coeff))
		}
		fes = append(fes, v)
	}
	return fes
}

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

// KeySchedule mirrors encryption.rs:key_schedule in-circuit.
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
	infoLo, infoHi := packInfoTo2FECircuit(api, info, infoLen)

	// Silo step: Poseidon(silo_sep, sharedSecret, infoLo, infoHi). t=5.
	siloed := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepSilo)),
		sharedSecret,
		infoLo,
		infoHi,
	})

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

// DeriveSharedSecret mirrors encryption.rs:derive_shared_secret in-circuit.
//
// Inputs:
//   - dh: 32-byte ECDH x-coordinate
//   - encCompressed: 33-byte compressed ephemeral pubkey
//   - rpkCompressed: 33-byte compressed recipient pubkey
//
// Returns the shared secret as a single field element.
//
// Width: 7 inputs to Poseidon -> t=8.
func DeriveSharedSecret(
	api frontend.API,
	dh [32]frontend.Variable,
	encCompressed [33]frontend.Variable,
	rpkCompressed [33]frontend.Variable,
) frontend.Variable {
	dhLo, dhHi := Pack32To2FECircuit(api, dh)
	encLo, encHi := Pack33To2FECircuit(api, encCompressed)
	rpkLo, rpkHi := Pack33To2FECircuit(api, rpkCompressed)
	sep := frontend.Variable(uint64(DomSepSharedSecret))
	return gadget.PoseidonHash(api, []frontend.Variable{
		sep, dhLo, dhHi, encLo, encHi, rpkLo, rpkHi,
	})
}
