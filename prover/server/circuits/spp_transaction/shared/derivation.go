package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Domain separators (32-bit ASCII tags) for the values a transact proof
// derives from its private random BlindingSeed and the first published nullifier.
// Mirror the constants in prover/server/prover-test/spp/protocol/utxo.go and
// sdk-libs/transaction/src/utxo.rs, both relative to the repository root.
//
// A nullifier enters the nullifier tree once, so each child is unique to one
// accepted transaction even if a client reuses a seed. The two children are
// domain-separated because they reach different parties: the output blinding
// seed is disclosed to the reader of an anonymous Sender bundle or a plaintext
// transfer, the private tx blinding to a policy or third-party co-prover.
// Recovering BlindingSeed from either child means inverting Poseidon, so a holder
// of one child cannot compute the other.
const (
	// OutputBlindingSeedDomainV1 = "TXOS"
	OutputBlindingSeedDomainV1 = 0x54584f53
	// OutputBlindingDomainV1 = "TXOB"
	OutputBlindingDomainV1 = 0x54584f42
	// PrivateTxBlindingDomainV1 = "TXPB"
	PrivateTxBlindingDomainV1 = 0x54585042
)

// RingOutputBlindingDomainV1 = "TXRB", mirrored by DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1 in sdk-libs/instruction/src/derivation.rs.
const RingOutputBlindingDomainV1 = 0x54585242

// DeriveOutputBlindingSeed derives the seed the output blindings come from.
func DeriveOutputBlindingSeed(api frontend.API, firstNullifier, blindingSeed frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		OutputBlindingSeedDomainV1, firstNullifier, blindingSeed,
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

// DeriveRingOutputBlinding derives a ring output's blinding from its ring secret, bound by the ring's audit proof and never by SPP.
func DeriveRingOutputBlinding(api frontend.API, firstNullifier, ringSecret, outputIndex frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		RingOutputBlindingDomainV1, firstNullifier, ringSecret, outputIndex,
	})
}

// DeriveRingRailOutputBlinding is TXOB over seed when inDefaultRing is 1 and TXRB over ringSecret when it is 0.
func DeriveRingRailOutputBlinding(
	api frontend.API,
	inDefaultRing,
	firstNullifier,
	seed,
	ringSecret frontend.Variable,
	outputIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		api.Select(inDefaultRing, OutputBlindingDomainV1, RingOutputBlindingDomainV1),
		firstNullifier,
		api.Select(inDefaultRing, seed, ringSecret),
		outputIndex,
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
