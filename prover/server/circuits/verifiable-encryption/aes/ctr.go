package aes

// AES-256-CTR mode, copied from confidential-transfers (encryption-utils/gcm)
// with the GCM authentication removed -- ciphertext integrity is enforced by a
// Poseidon ciphertext hash folded into the public input hash, not a GCM tag.

import (
	"github.com/consensys/gnark/frontend"
)

// AESCTRBlock encrypts a single plaintext block using AES in CTR mode.
// The counter is derived from the IV using GCM convention:
//
//	J0 = IV || 0x00000001
//	counter = Increment32^blockNum(J0)
//
// blockNum=1 gives counter with last 4 bytes = 0x00000002, etc.
// Creates a standalone AESGadget internally.
func AESCTRBlock(api frontend.API, key [32]frontend.Variable, iv [12]frontend.Variable, plaintext [16]frontend.Variable, blockNum int) [16]frontend.Variable {
	// Start with J0 = IV || 0x00000001
	counter := MakeJ0(api, iv)

	// Increment blockNum times
	for i := 0; i < blockNum; i++ {
		counter = Increment32(api, counter)
	}

	// Encrypt counter to produce keystream
	keystream := AES256Block(api, counter, key)

	// XOR plaintext with keystream
	return XorBytes16(api, plaintext, keystream)
}

// AESCTRBlockWithGadget is the same as AESCTRBlock but uses a shared AESGadget.
func AESCTRBlockWithGadget(api frontend.API, g *AESGadget, key [32]frontend.Variable, iv [12]frontend.Variable, plaintext [16]frontend.Variable, blockNum int) [16]frontend.Variable {
	// Start with J0 = IV || 0x00000001
	counter := MakeJ0(api, iv)

	// Increment blockNum times
	for i := 0; i < blockNum; i++ {
		counter = Increment32(api, counter)
	}

	// Encrypt counter to produce keystream
	keystream := AES256BlockWithGadget(g, counter, key[:])

	// XOR plaintext with keystream
	return XorBytes16(api, plaintext, keystream)
}

// AESCTR encrypts a single plaintext block using AES-CTR mode.
// This is equivalent to AESCTRBlock with blockNum=1.
func AESCTR(api frontend.API, key [32]frontend.Variable, iv [12]frontend.Variable, plaintext [16]frontend.Variable) [16]frontend.Variable {
	return AESCTRBlock(api, key, iv, plaintext, 1)
}

// CTREncrypt AES-256-CTR encrypts plaintext (any length) into a ciphertext of
// equal length, advancing the counter per 16-byte block and XORing only the
// available bytes of the final partial block. Uses a shared AESGadget so callers
// that encrypt several plaintexts in one circuit reuse the lookup tables.
func CTREncrypt(api frontend.API, g *AESGadget, key [32]frontend.Variable, nonce [12]frontend.Variable, plaintext []frontend.Variable) []frontend.Variable {
	ciphertext := make([]frontend.Variable, len(plaintext))
	counter := MakeJ0(api, nonce)
	for offset := 0; offset < len(plaintext); offset += 16 {
		counter = Increment32(api, counter)
		keystream := AES256BlockWithGadget(g, counter, key[:])
		for j := 0; j < 16 && offset+j < len(plaintext); j++ {
			ciphertext[offset+j] = XorByte(api, plaintext[offset+j], keystream[j])
		}
	}
	return ciphertext
}

// Increment32 increments the last 4 bytes of a 16-byte counter block
// The counter is big-endian (bytes 12-15), wrapping on overflow
func Increment32(api frontend.API, counter [16]frontend.Variable) [16]frontend.Variable {
	var result [16]frontend.Variable

	// Copy first 12 bytes unchanged (IV portion)
	for i := 0; i < 12; i++ {
		result[i] = counter[i]
	}

	// Extract the 32-bit counter (big-endian: bytes 12-15)
	// counter_value = counter[12]*2^24 + counter[13]*2^16 + counter[14]*2^8 + counter[15]
	counterValue := api.Add(
		api.Mul(counter[12], 1<<24),
		api.Add(
			api.Mul(counter[13], 1<<16),
			api.Add(
				api.Mul(counter[14], 1<<8),
				counter[15],
			),
		),
	)

	// Increment and wrap at 2^32
	// new_value = (counter_value + 1) mod 2^32
	newValue := api.Add(counterValue, 1)

	// Convert to 33 bits to handle overflow
	newBits := api.ToBinary(newValue, 33)

	// Take only lower 32 bits (wrap around)
	lower32Bits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		lower32Bits[i] = newBits[i]
	}

	// Convert back to 4 bytes (big-endian)
	// Byte 12 = bits 24-31 (MSB)
	// Byte 13 = bits 16-23
	// Byte 14 = bits 8-15
	// Byte 15 = bits 0-7 (LSB)
	byte15Bits := lower32Bits[0:8]
	byte14Bits := lower32Bits[8:16]
	byte13Bits := lower32Bits[16:24]
	byte12Bits := lower32Bits[24:32]

	result[15] = api.FromBinary(byte15Bits...)
	result[14] = api.FromBinary(byte14Bits...)
	result[13] = api.FromBinary(byte13Bits...)
	result[12] = api.FromBinary(byte12Bits...)

	return result
}

// MakeJ0 creates the initial counter block J0 from a 12-byte IV
// J0 = IV || 0x00000001
func MakeJ0(api frontend.API, iv [12]frontend.Variable) [16]frontend.Variable {
	var j0 [16]frontend.Variable

	// Copy IV to first 12 bytes
	for i := 0; i < 12; i++ {
		j0[i] = iv[i]
	}

	// Set counter to 1 (big-endian)
	j0[12] = frontend.Variable(0)
	j0[13] = frontend.Variable(0)
	j0[14] = frontend.Variable(0)
	j0[15] = frontend.Variable(1)

	return j0
}

// XorByte computes XOR of two byte values.
func XorByte(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 8)
	bBits := api.ToBinary(b, 8)

	resultBits := make([]frontend.Variable, 8)
	for i := 0; i < 8; i++ {
		ab := api.Mul(aBits[i], bBits[i])
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(2, ab))
	}

	return api.FromBinary(resultBits...)
}

// XorBytes16 computes XOR of two 16-byte arrays.
func XorBytes16(api frontend.API, a, b [16]frontend.Variable) [16]frontend.Variable {
	var result [16]frontend.Variable
	for i := 0; i < 16; i++ {
		result[i] = XorByte(api, a[i], b[i])
	}
	return result
}
