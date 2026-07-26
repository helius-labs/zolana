package shared

import (
	"github.com/consensys/gnark/frontend"
)

// Signers is a transaction's single source of truth for who signed it: one entry
// per input slot, built once per proof by the rail's signer builder, and masked
// to 0 for slots that carry no content. Every later check that needs a signature
// resolves against it instead of re-deriving the rail's rule. Rails build it at
// the granularity their checks can resolve: the signer pk hash (what the input
// ownership binding needs, and what the default zone's public output owner tags
// carry) or the owner hash a signer proved (SignerOwners, for the custom zone
// where output owners stay private).
type Signers []frontend.Variable

// Contains returns 1 iff identity is non-zero and equals one of the signers. The
// non-zero requirement keeps masked slots from ever matching.
func (s Signers) Contains(api frontend.API, identity frontend.Variable) frontend.Variable {
	prod := frontend.Variable(1)
	for _, signer := range s {
		prod = api.Mul(prod, api.Sub(identity, signer))
	}
	return api.Mul(api.IsZero(prod), api.Sub(1, api.IsZero(identity)))
}

// ContainsEach returns one bit per identity, set when that identity signed. The
// variants use it to hand Transaction.Constrain the per-output-slot bit a
// data-carrying output requires.
func (s Signers) ContainsEach(api frontend.API, identities []frontend.Variable) []frontend.Variable {
	signed := make([]frontend.Variable, len(identities))
	for i, identity := range identities {
		signed[i] = s.Contains(api, identity)
	}
	return signed
}

// Returns array of pubkeys that signed the Solana transaction.
func EddsaOnlySigners(api frontend.API, inputs []Input, ownerPkHashes []frontend.Variable) Signers {
	signers := make(Signers, len(inputs))
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		pkHash := ownerPkHashes[i]
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	return signers
}
