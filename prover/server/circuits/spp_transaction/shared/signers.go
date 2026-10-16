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

// WithoutPayer drops the payer, leaving the owner signers and the zero padding.
// The host builds the vector with the payer first and the owner signers
// deduplicated; the circuit checks neither.
func (s Signers) WithoutPayer() Signers {
	return s[1:]
}

// ContainsEach returns one bit per identity, set when that identity signed.
func (signers Signers) ContainsEach(api frontend.API, identities []frontend.Variable) []frontend.Variable {
	signed := make([]frontend.Variable, len(identities))
	for i, identity := range identities {
		signed[i] = signers.Contains(api, identity)
	}
	return signed
}

// ConfidentialEd25519Signers returns the private owner identities of content-bearing
// inputs. Dummy inputs contribute zero.
func ConfidentialEd25519Signers(api frontend.API, inputs []Input, ownerPkHashes []frontend.Variable) Signers {
	signers := make(Signers, len(inputs))
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		pkHash := ownerPkHashes[i]
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	return signers
}

// AuthorizedEd25519InputOwners resolves the private per-input owner identities and
// requires every content-bearing input to be authorized by the unified signer
// vector. The vector contains the payer first, then appended Solana signers.
func AuthorizedEd25519InputOwners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorized Signers,
) Signers {
	owners := ConfidentialEd25519Signers(api, inputs, ownerPkHashes)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		AssertWhen(api, carriesContent, authorized.Contains(api, ownerPkHashes[i]))
	}
	return owners
}

// HiddenOwnerSigners resolves a zero owner tag to the signature-checked hidden
// owner. Nonzero tags must remain authorized public Solana signer identities.
func HiddenOwnerSigners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorizedEddsa Signers,
	hiddenOwnerPkHash frontend.Variable,
	hiddenSignatureValid frontend.Variable,
) Signers {
	signers := make(Signers, len(inputs))
	hasHiddenInput := frontend.Variable(0)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		isHidden := api.IsZero(ownerPkHashes[i])
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		pkHash := api.Select(isHidden, hiddenOwnerPkHash, ownerPkHashes[i])
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		AssertWhen(api, api.Mul(carriesContent, isHidden), hiddenSignatureValid)
		AssertWhen(
			api,
			api.Mul(carriesContent, api.Sub(1, isHidden)),
			authorizedEddsa.Contains(api, ownerPkHashes[i]),
		)
		hasHiddenInput = api.Add(hasHiddenInput, api.Mul(carriesContent, isHidden))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	// This rail needs at least one hidden-owner input. Ordinary all-Ed25519
	// transactions use ConfidentialRingEd25519.
	api.AssertIsDifferent(hasHiddenInput, 0)
	return signers
}

// AssertHiddenRingOwner keeps the hidden owner out of public data. An address
// nullifier is computable from (owner, seed), so no slot may create an address.
func AssertHiddenRingOwner(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	signers Signers,
	hiddenOwner frontend.Variable,
) {
	for i, in := range inputs {
		api.AssertIsDifferent(in.Utxo.Domain, AddressDomain)
		hidden := api.Mul(in.isUtxo(api), api.IsZero(ownerPkHashes[i]))
		AssertWhen(api, hidden, api.Sub(1, api.IsZero(in.Utxo.RingProgramID)))
	}
	for _, signer := range signers {
		api.AssertIsDifferent(signer, hiddenOwner)
	}
}
