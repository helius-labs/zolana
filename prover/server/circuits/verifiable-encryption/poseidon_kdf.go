package verifiableencryption

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

const (
	DomSepSilo  uint32 = 0x544d5349
	DomSepKey   uint32 = 0x544d534b
	DomSepNonce uint32 = 0x544d534e
	// Poseidon accepts at most 16 inputs; the domain and secret use two.
	maxKdfInfoBytes = 14 * gadget.HashBytesChunkSize
)

// KeySchedule derives an AES-256 key and 12-byte nonce from a shared secret.
// The compile-time info label is at most 434 bytes. Its final 31-byte chunk
// (including a full final chunk) must not start with zero, so differently sized
// labels cannot pack into the same field elements. Empty info is allowed.
func KeySchedule(
	api frontend.API,
	sharedSecret frontend.Variable,
	info []byte,
) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	if len(info) > maxKdfInfoBytes {
		panic(fmt.Sprintf("kdf: info of %d bytes, at most %d", len(info), maxKdfInfoBytes))
	}
	if len(info) > 0 {
		lastChunk := (len(info) - 1) / gadget.HashBytesChunkSize * gadget.HashBytesChunkSize
		if info[lastChunk] == 0 {
			panic("kdf: final info chunk must not start with zero")
		}
	}
	infoBytes := make([]frontend.Variable, len(info))
	for i, b := range info {
		infoBytes[i] = b
	}
	infoFields := gadget.PackBytesBE(api, infoBytes)

	siloInputs := []frontend.Variable{
		frontend.Variable(uint64(DomSepSilo)),
		sharedSecret,
	}
	siloInputs = append(siloInputs, infoFields...)
	siloed := gadget.PoseidonHash(api, siloInputs)

	keyLo := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey)),
		siloed,
	})
	keyHi := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey + 1)),
		siloed,
	})

	keyLoBytes := FieldToBytesBE(api, keyLo, 32)
	keyHiBytes := FieldToBytesBE(api, keyHi, 32)
	for i := 0; i < 16; i++ {
		key[i] = keyHiBytes[16+i]
		key[16+i] = keyLoBytes[16+i]
	}

	nonceRaw := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepNonce)),
		siloed,
	})
	nonceBytes := FieldToBytesBE(api, nonceRaw, 32)
	for i := 0; i < 12; i++ {
		nonce[i] = nonceBytes[20+i]
	}

	return key, nonce
}
