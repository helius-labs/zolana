// Package blinding holds the deterministic output-blinding derivation shared
// by the dynamic-swap circuits (settle recipient payout, cancel refund).
package blinding

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// RecipientBlindingDomain is folded into the settle recipient output's
// blinding derivation. It MUST stay in sync with dynamic-swap-prover's Rust
// copy and be distinct from escrow_cancel's RefundBlindingDomain -- the cancel
// refund derives from the same order blinding.
const RecipientBlindingDomain uint64 = 0x53544C5245434950 // "STLRECIP"

// blindingBits truncates the Poseidon output to a 31-byte blinding (the SPP
// Blinding width), matching the Rust derivation's [1..32] byte slice.
const blindingBits = 248

// DeriveOutputBlinding folds one input blinding and a per-slot domain into a
// single 31-byte blinding. Truncating the 254-bit Poseidon output to its low
// 248 bits mirrors the Rust helper, which keeps bytes [1..32] of the hash.
func DeriveOutputBlinding(api frontend.API, blinding frontend.Variable, domain uint64) frontend.Variable {
	full := gadget.PoseidonHash(api, []frontend.Variable{
		blinding,
		frontend.Variable(domain),
	})
	bits := api.ToBinary(full, 254)
	return api.FromBinary(bits[:blindingBits]...)
}
