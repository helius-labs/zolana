package shared

import (
	"github.com/consensys/gnark/frontend"
)

type Signers []frontend.Variable

// Contains returns 1 iff identity is non-zero and equals one of the signers.
func (s Signers) Contains(api frontend.API, identity frontend.Variable) frontend.Variable {
	prod := frontend.Variable(1)
	for _, signer := range s {
		prod = api.Mul(prod, api.Sub(identity, signer))
	}
	return api.Mul(api.IsZero(prod), api.Sub(1, api.IsZero(identity)))
}

// ContainsEach returns one bit per identity, set when that identity signed.
func (signers Signers) ContainsEach(api frontend.API, identities []frontend.Variable) []frontend.Variable {
	signed := make([]frontend.Variable, len(identities))
	for i, identity := range identities {
		signed[i] = signers.Contains(api, identity)
	}
	return signed
}

// EddsaOnlySigners returns the owner identities of content-bearing inputs whose
// Solana accounts signed the transaction. A dummy's signer index does not make
// its unbound public owner tag an owner identity.
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
