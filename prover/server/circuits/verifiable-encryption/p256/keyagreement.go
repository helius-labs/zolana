package p256

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
)

type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

type (
	agreementField   = emulated.Field[emulated.P256Fp]
	agreementElement = emulated.Element[emulated.P256Fp]
	agreementPoint   = sw_emulated.AffinePoint[emulated.P256Fp]
)

const uncompressedPrefix = 0x04

// ComputeKeyAgreement validates the supplied key material and derives the
// packed public keys and shared P-256 ECDH x-coordinate.
func ComputeKeyAgreement(
	api frontend.API,
	ephemeralSecretKey [32]frontend.Variable,
	recipientPubkey [65]frontend.Variable,
) KeyAgreement {
	c := newP256Curve(api)
	fp := newAgreementField(api)

	api.AssertIsEqual(recipientPubkey[0], uncompressedPrefix)
	recipient, recipientParity := canonicalRecipient(api, c, fp, recipientPubkey[1:])

	ephemeral := DerivePublicKey(api, ephemeralSecretKey)
	shared := c.ScalarMul(recipient, ephemeral.scalar)

	sharedX, _ := canonicalFpBytes(api, fp, &shared.X)

	var keyAgreement KeyAgreement
	keyAgreement.RecipientLo, keyAgreement.RecipientHi = packCompressedPoint(api, recipientParity, recipientPubkey[1:33])
	keyAgreement.EphemeralLo, keyAgreement.EphemeralHi = ephemeral.Packed(api)
	keyAgreement.SharedLo, keyAgreement.SharedHi = packSharedX(api, sharedX[:])
	return keyAgreement
}

// canonicalRecipient decodes a finite, on-curve point from x || y bytes and
// returns it with the parity of y. The parity is read from the last y byte,
// which is the canonical parity only because the same function has already
// forced y < p, so the two cannot be separated by a refactor.
func canonicalRecipient(
	api frontend.API,
	c *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr],
	fp *agreementField,
	bytes []frontend.Variable,
) (*agreementPoint, frontend.Variable) {
	rc := rangecheck.New(api)
	for _, b := range bytes {
		rc.Check(b, 8)
	}

	recipient := &agreementPoint{
		X: *fp.NewElement(agreementLimbs(api, bytes[0:32])),
		Y: *fp.NewElement(agreementLimbs(api, bytes[32:64])),
	}
	fp.AssertIsInRange(&recipient.X)
	fp.AssertIsInRange(&recipient.Y)
	c.AssertIsOnCurve(recipient)
	// AssertIsOnCurve admits (0,0) as its infinity encoding. A recipient at
	// infinity makes the shared point infinity too, so the shared secret would
	// depend only on public values and anyone could decrypt the envelope.
	api.AssertIsEqual(api.And(fp.IsZero(&recipient.X), fp.IsZero(&recipient.Y)), 0)

	return recipient, api.ToBinary(bytes[63], 8)[0]
}

func agreementLimbs(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	limbs := make([]frontend.Variable, 4)
	for i := range limbs {
		end := len(bytes) - 8*i
		limbs[i] = gadget.BytesToField(api, bytes[end-8:end])
	}
	return limbs
}

func canonicalFpBytes(api frontend.API, fp *agreementField, e *agreementElement) ([32]frontend.Variable, frontend.Variable) {
	bits := fp.ToBitsCanonical(e)
	var bytes [32]frontend.Variable
	copy(bytes[:], gadget.BitsToBytesBE(api, bits))
	return bytes, bits[0]
}

// packCompressedPoint splits a 33-byte SEC1-compressed P-256 public key
// ((0x02 + parity) || x) into two field elements. This is the source of truth
// for the packing; the Rust program and SDK mirror it.
//
// Byte layout (both elements are 32-byte big-endian integers):
//
//	lo = 0x00 || key[0..31]              (the SEC1 prefix key[0] is the most
//	                                      significant data byte)
//	hi = key[31] * 256 + key[32]         (a 16-bit value; as a 32-byte
//	                                      big-endian encoding hi[30] = key[31],
//	                                      hi[31] = key[32], rest zero)
//
// Callers must range-check every x byte to 8 bits, otherwise the packing is
// not injective.
func packCompressedPoint(api frontend.API, parity frontend.Variable, x []frontend.Variable) (lo, hi frontend.Variable) {
	prefix := api.Mul(api.Add(2, parity), new(big.Int).Lsh(big.NewInt(1), 240))
	return api.Add(prefix, gadget.BytesToField(api, x[0:30])), gadget.BytesToField(api, x[30:32])
}

// packSharedX splits the 32-byte big-endian ECDH x-coordinate into two field
// elements, the protocol's packing for a 32-byte value that does not fit one
// BN254 element. The Rust host derivation mirrors it.
//
//	lo = 0x00 || x[0..31]   (x[0] is the most significant data byte)
//	hi = x[31]              (a single byte, value < 2^8)
//
// Callers must range-check every byte to 8 bits, otherwise the packing is not
// injective.
func packSharedX(api frontend.API, x []frontend.Variable) (lo, hi frontend.Variable) {
	return gadget.BytesToField(api, x[0:31]), x[31]
}
