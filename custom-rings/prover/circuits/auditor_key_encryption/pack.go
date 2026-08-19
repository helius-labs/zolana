package auditor_key_encryption

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// DomSepCRShared is the shared-secret domain separator, the ASCII tag "CR_S"
// read as a big-endian 32-bit integer and used as the first Poseidon input of
// DeriveAuditSharedSecret. The Rust host derivation
// (custom-ring-tests/sdk/src/encryption.rs) MUST use the same value.
const DomSepCRShared uint32 = 0x43525f53 // "CR_S"

// pack256 builds 256^k as a *big.Int constant, for k in 0..31.
func pack256(k int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(8*k))
}

// Pack32To2FECircuit splits 32 bytes into the two field elements the protocol
// uses for a 32-byte value that does not fit one BN254 element. This file is
// the source of truth for the packing; the Rust program and SDK mirror it.
//
// Byte layout (both elements are 32-byte big-endian integers):
//
//	lo = 0x00 || bytes[0..31]   (bytes[0] is the most significant data byte,
//	                             bytes[30] the least; one zero pad byte on top)
//	hi = bytes[31]              (a single byte, value < 2^8)
//
// Equivalently lo = sum_{i=0..30} bytes[i] * 256^(30-i) and hi = bytes[31].
// Callers must range-check every input byte to 8 bits, otherwise the packing is
// not injective.
func Pack32To2FECircuit(api frontend.API, bytes [32]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for i := 0; i < 31; i++ {
		// Position 30-i: byte 0 is the most significant, byte 30 the least.
		lo = api.Add(lo, api.Mul(bytes[i], pack256(30-i)))
	}
	hi = bytes[31]
	return lo, hi
}

// Pack33To2FECircuit splits a 33-byte SEC1-compressed P-256 public key into two
// field elements. This file is the source of truth for the packing; the Rust
// program and SDK mirror it.
//
// Byte layout (both elements are 32-byte big-endian integers):
//
//	lo = 0x00 || key[0..31]              (same shape as Pack32To2FECircuit: the
//	                                      SEC1 prefix key[0] is the most
//	                                      significant data byte)
//	hi = key[31] * 256 + key[32]         (a 16-bit value; as a 32-byte
//	                                      big-endian encoding hi[30] = key[31],
//	                                      hi[31] = key[32], rest zero)
//
// Equivalently lo = sum_{i=0..30} key[i] * 256^(30-i).
// Callers must range-check every input byte to 8 bits, otherwise the packing is
// not injective.
func Pack33To2FECircuit(api frontend.API, key [33]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for i := 0; i < 31; i++ {
		lo = api.Add(lo, api.Mul(key[i], pack256(30-i)))
	}
	hi = api.Add(api.Mul(key[31], big.NewInt(256)), key[32])
	return lo, hi
}

// DeriveAuditSharedSecret binds the raw ECDH output to both public keys that
// produced it, so the AES key schedule input is a single field element that
// cannot be replayed under a different key pair:
//
//	shared_secret = Poseidon(DomSepCRShared,
//	                         dh_lo, dh_hi,
//	                         eph_pk_lo, eph_pk_hi,
//	                         auditor_pk_lo, auditor_pk_hi)
//
// dh is the 32-byte big-endian x-coordinate of eph_sk * auditor_pk (packed with
// Pack32To2FECircuit), ephCompressed and auditorCompressed are the 33-byte SEC1
// compressed keys (packed with Pack33To2FECircuit). The Rust host derivation
// MUST mirror this input order element for element.
func DeriveAuditSharedSecret(
	api frontend.API,
	dh [32]frontend.Variable,
	ephCompressed [33]frontend.Variable,
	auditorCompressed [33]frontend.Variable,
) frontend.Variable {
	dhLo, dhHi := Pack32To2FECircuit(api, dh)
	ephLo, ephHi := Pack33To2FECircuit(api, ephCompressed)
	auditorLo, auditorHi := Pack33To2FECircuit(api, auditorCompressed)
	return gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepCRShared)),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
}
