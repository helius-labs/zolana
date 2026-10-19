package encryption

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
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

	rc := rangecheck.New(api)
	copy(key[:16], gadget.FieldLowBytesBE(api, rc, keyHi, 16))
	copy(key[16:], gadget.FieldLowBytesBE(api, rc, keyLo, 16))

	// Single Poseidon call for the GCM nonce (last 12 bytes of the output).
	nonceRaw := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepNonce)),
		siloed,
	})
	copy(nonce[:], gadget.FieldLowBytesBE(api, rc, nonceRaw, 12))

	return key, nonce
}
