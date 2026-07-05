package squadskeyencryption

import (
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/aes"
	zoneutils "zolana/prover/circuits/zone-utils"
	"zolana/prover/circuits/zone-utils/p256"
)

// p256ScalarLimbBits splits a P-256 scalar into 128-bit hi/lo limbs for the
// Poseidon commitment, matching the zone viewing-key commitment.
const p256ScalarLimbBits = 128

// p256ScalarBits decomposes an emulated P-256 scalar into its canonical
// LSB-first 256-bit form, so a full-range scalar never aliases mod BN254.
func p256ScalarBits(api frontend.API, sk emulated.Element[emulated.P256Fr]) ([]frontend.Variable, error) {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	return fr.ToBitsCanonical(&sk), nil
}

// scalarBytesBE packs LSB-first scalar bits into 32 big-endian bytes: byte p
// (little-endian) holds bits [p*8, p*8+8), placed at position 31-p.
func scalarBytesBE(api frontend.API, skBits []frontend.Variable) [32]frontend.Variable {
	var skBytes [32]frontend.Variable
	for p := 0; p < 32; p++ {
		skBytes[31-p] = gnarkbits.FromBinary(api, skBits[p*8:p*8+8])
	}
	return skBytes
}

// viewingKeyCommitmentAndBytes derives, from the shared viewing scalar, both the
// Poseidon commitment Poseidon(skLow, skHigh) (the published
// shared_viewing_key_commitment) and the 32-byte big-endian scalar used as the
// plaintext encrypted to every recipient.
func viewingKeyCommitmentAndBytes(api frontend.API, sk emulated.Element[emulated.P256Fr]) (frontend.Variable, [32]frontend.Variable, error) {
	skBits, err := p256ScalarBits(api, sk)
	if err != nil {
		return nil, [32]frontend.Variable{}, err
	}
	skLow := gnarkbits.FromBinary(api, skBits[:p256ScalarLimbBits])
	skHigh := gnarkbits.FromBinary(api, skBits[p256ScalarLimbBits:])
	commitment := gadget.PoseidonHash(api, []frontend.Variable{skLow, skHigh})
	return commitment, scalarBytesBE(api, skBits), nil
}

// ecdhEncrypt is one verifiable encryption to a recipient and returns the
// Poseidon ciphertext hash to fold into the public input hash: ECDH against the
// recipient key under the shared ephemeral, Poseidon key schedule, AES-CTR over
// the plaintext. Integrity comes from the returned hash, not a GCM tag.
func ecdhEncrypt(
	api frontend.API,
	g *aes.AESGadget,
	ephBytes [32]frontend.Variable,
	ephPkComp [33]frontend.Variable,
	rpkUncompressed [65]frontend.Variable,
	rpkComp [33]frontend.Variable,
	plaintext []frontend.Variable,
) frontend.Variable {
	dh := p256.ECDH(api, ephBytes, rpkUncompressed)
	sharedSecret := zoneutils.DeriveSharedSecret(api, dh, ephPkComp, rpkComp)
	key, nonce := zoneutils.KeySchedule(api, sharedSecret, nil, 0)
	ciphertext := aes.CTREncrypt(api, g, key, nonce, plaintext)
	return gadget.PoseidonHash(api, zoneutils.PackBytesBE(api, ciphertext, 16))
}
