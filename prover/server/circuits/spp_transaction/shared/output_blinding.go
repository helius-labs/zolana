package shared

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// OutputBlindingDomainV1 is the 32-bit ASCII tag "TXOB". It must match
// DOMAIN_TRANSACT_OUTPUT_BLINDING_V1 in sdk-libs/transaction/src/utxo.rs.
const OutputBlindingDomainV1 = 0x54584f42

// DeriveOutputBlinding binds one output's blinding to the transaction's first
// single-use nullifier, one private transaction seed, and the physical output
// slot. The slot is the final zero-based position after padding.
func DeriveOutputBlinding(
	api frontend.API,
	firstNullifier,
	seed frontend.Variable,
	outputIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		OutputBlindingDomainV1,
		firstNullifier,
		seed,
		outputIndex,
	})
}
