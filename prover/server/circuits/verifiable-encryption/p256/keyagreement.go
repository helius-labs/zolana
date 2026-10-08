package p256

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve"
)

// KeyAgreement packs the recipient key, the ephemeral key and the shared
// x-coordinate into two field elements each.
//
// Compressed keys ((0x02 + parity) || x):
//
//	lo = 0x00 || key[0..31]   hi = key[31] * 256 + key[32]
//
// Shared x-coordinate:
//
//	lo = 0x00 || x[0..31]     hi = x[31]
//
// This is the source of truth for the packing; the Rust program and SDK mirror it.
type KeyAgreement = emcurve.KeyAgreement

// ComputeKeyAgreement validates the supplied key material and derives the
// packed public keys and shared P-256 ECDH x-coordinate.
func ComputeKeyAgreement(
	api frontend.API,
	ephemeralSecretKey [32]frontend.Variable,
	recipientPubkey [65]frontend.Variable,
) KeyAgreement {
	emcurve.AssertBytes(api, ephemeralSecretKey[:])
	return emcurve.AgreeKey(api, ephemeralSecretKey, recipientPubkey)
}
