package x25519

import "github.com/consensys/gnark/frontend"

// KeyAgreement binds the recipient encoding, derived ephemeral public key,
// and shared secret. Each Lo field is the first 31 encoded bytes interpreted
// as a big-endian integer. Each Hi field is the final byte. These are byte
// chunks for a transcript, despite X25519's little-endian coordinate encoding.
type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

// AgreeKey exposes the complete binding relation to transcript mutation tests.
func AgreeKey(api frontend.API, ephemeralSk, recipientPk [32]frontend.Variable) KeyAgreement {
	// 1. Prove ECDH and public-key derivation against the same scalar bytes.
	shared := ECDH(api, ephemeralSk, recipientPk)
	ephemeral := ScalarMulGenerator(api, ephemeralSk)
	// 2. Bind all three byte encodings into injective transcript chunks.
	var result KeyAgreement
	result.RecipientLo, result.RecipientHi = packKeyBytes(api, recipientPk)
	result.EphemeralLo, result.EphemeralHi = packKeyBytes(api, ephemeral)
	result.SharedLo, result.SharedHi = packKeyBytes(api, shared)
	return result
}

// packKeyBytes packs an already byte-constrained encoding into a 31-byte
// big-endian integer and its last byte. Since 2^248 is below BN254 Fr, this
// packing is injective. It does not reinterpret the X25519 coordinate endian.
func packKeyBytes(api frontend.API, encoded [32]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for _, b := range encoded[:31] {
		lo = api.Add(api.Mul(lo, 256), b)
	}
	return lo, encoded[31]
}
