package ringutils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"

	"github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// DomSepSharedSecret binds the tagged X25519 agreement transcript.
const DomSepSharedSecret uint32 = 0x43545f53 // "CT_S"

// KdfDomainSep separates the squads ring Poseidon KDF chain from plain Poseidon
// hashes (e.g. the viewing-key commitment), so an intermediate such as view_root
// can never equal a published commitment computed over the same key. MUST be
// mirrored byte-for-byte by the on-chain program and the auditor's blinding
// recompute.
var KdfDomainSep = new(big.Int).SetBytes([]byte("TSPP/kdf"))

// PoseidonKDF is one keyed step of the ring KDF chain: a Poseidon hash with
// KdfDomainSep prepended as the first input. Spec: squads_policy_program.md,
// Ring Proof "Change-blinding derivation".
func PoseidonKDF(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, append([]frontend.Variable{KdfDomainSep}, inputs...))
}

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

// ForceEqualIfEnabled enforces a == b when enabled is non-zero by
// constraining (a-b)*enabled === 0.
func ForceEqualIfEnabled(api frontend.API, a, b, enabled frontend.Variable) {
	api.AssertIsEqual(api.Mul(api.Sub(a, b), enabled), frontend.Variable(0))
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

// KeySchedule uses the shared verifiable-encryption key schedule.
func KeySchedule(api frontend.API, sharedSecret frontend.Variable, info []frontend.Variable, infoLen int) ([32]frontend.Variable, [12]frontend.Variable) {
	return encryption.KeySchedule(api, sharedSecret, info, infoLen)
}

// DeriveSharedSecret mirrors encryption.rs:derive_shared_secret in-circuit.
//
// Inputs:
//   - dh: 32-byte ECDH x-coordinate
//   - encCompressed: 33-byte tagged ephemeral X25519 public key
//   - rpkCompressed: 33-byte tagged recipient X25519 public key
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
