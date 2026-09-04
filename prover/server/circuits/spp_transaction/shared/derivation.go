package shared

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// Domain separators (32-bit ASCII tags) for the values a transact proof
// derives from its single random TxSecret and the first published nullifier.
// Mirror the constants in prover-test/spp/protocol/utxo.go and
// sdk-libs/transaction/src/utxo.rs.
//
// A nullifier enters the nullifier tree once, so each child is unique to one
// accepted transaction even if a client reuses a secret. The two children are
// domain-separated because they reach different parties: the output blinding
// seed is disclosed to the reader of an anonymous Sender bundle or a plaintext
// transfer, the private tx blinding to a policy or third-party co-prover.
// Recovering TxSecret from either child means inverting Poseidon, so a holder
// of one child cannot compute the other.
const (
	// OutputBlindingSeedDomainV1 = "TXOS"
	OutputBlindingSeedDomainV1 = 0x54584f53
	// OutputBlindingDomainV1 = "TXOB"
	OutputBlindingDomainV1 = 0x54584f42
	// PrivateTxBlindingDomainV1 = "TXPB"
	PrivateTxBlindingDomainV1 = 0x54585042
)

// DeriveOutputBlindingSeed derives the seed the output blindings come from.
func DeriveOutputBlindingSeed(api frontend.API, firstNullifier, txSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		OutputBlindingSeedDomainV1, firstNullifier, txSecret,
	})
}

// DeriveOutputBlinding derives the blinding of the output in slot outputIndex
// from the output blinding seed. The slot is the final zero-based position
// after padding.
func DeriveOutputBlinding(
	api frontend.API,
	firstNullifier,
	seed frontend.Variable,
	outputIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		OutputBlindingDomainV1, firstNullifier, seed, outputIndex,
	})
}

// DerivePrivateTxBlinding derives the final private_tx_hash preimage element.
// It is not a public signal: the other preimage elements are public or
// computable, so a blinding an observer knows would let it test candidate
// input UTXO hashes against the published hash. Merge passes the owner's
// nullifier secret as the secret.
func DerivePrivateTxBlinding(api frontend.API, firstNullifier, secret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		PrivateTxBlindingDomainV1, firstNullifier, secret,
	})
}
