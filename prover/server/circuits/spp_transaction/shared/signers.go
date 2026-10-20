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

// ConfidentialEddsaSigners returns the private owner identities of content-bearing
// inputs. Dummy inputs contribute zero.
func ConfidentialEddsaSigners(api frontend.API, inputs []Input, ownerPkHashes []frontend.Variable) Signers {
	signers := make(Signers, len(inputs))
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		pkHash := ownerPkHashes[i]
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	return signers
}

// AuthorizedEddsaInputOwners resolves the private per-input owner identities and
// requires every content-bearing input to be authorized by the deduplicated
// owner-signer vector. Paying fees alone does not authorize an input.
func AuthorizedEddsaInputOwners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorized Signers,
) Signers {
	owners := ConfidentialEddsaSigners(api, inputs, ownerPkHashes)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		AssertWhen(api, carriesContent, authorized.Contains(api, ownerPkHashes[i]))
	}
	return owners
}

// HiddenOwnerSigners resolves the zero owner-tag sentinel to the hidden owner.
// Non-zero tags remain Solana signer identities.
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
	// AnonymousRingEddsa needs a hidden-owner input. Transactions with only
	// public signers use ConfidentialRingEddsa.
	api.AssertIsDifferent(hasHiddenInput, 0)
	return signers
}

// AssertDefaultHiddenOwner publishes the hidden identity iff at least one
// spent hidden-owner UTXO belongs to the default ring. Ring-only hidden inputs
// keep the owner private and require the public field to be zero.
//
// A ring hidden input is an anonymous spend, so the identity must stay out of
// the transaction's public data: no default-ring hidden input may force it
// into defaultOwnerPkHash, and no published output owner tag may equal it.
// Publishing the identity without a ring hidden input is allowed; moving a
// default-ring UTXO into the ring names the depositor, not a ring spender.
//
// Address slots count as neither. An address has RingProgramID 0
// (checkAddress), so treating it as a default-ring input would publish the
// identity of a ring spender who creates an address in the same proof and
// would forbid that combination. Creating an address spends nothing, so it
// does not force the identity into public data; an address-only proof
// publishes zero.
func AssertDefaultHiddenOwner(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	publishedOutputOwnerPkHashes []frontend.Variable,
	hiddenOwnerPkHash frontend.Variable,
	defaultOwnerPkHash frontend.Variable,
) {
	hasDefaultHidden := frontend.Variable(0)
	hasRingHidden := frontend.Variable(0)
	for i, in := range inputs {
		isHidden := api.IsZero(ownerPkHashes[i])
		isDefaultRing := api.IsZero(in.Utxo.RingProgramID)
		realHidden := api.Mul(in.isUtxo(api), isHidden)
		hasDefaultHidden = api.Add(hasDefaultHidden, api.Mul(realHidden, isDefaultRing))
		hasRingHidden = api.Add(hasRingHidden, api.Mul(realHidden, api.Sub(1, isDefaultRing)))
	}
	hasDefaultHidden = api.Sub(1, api.IsZero(hasDefaultHidden))
	hasRingHidden = api.Sub(1, api.IsZero(hasRingHidden))
	api.AssertIsEqual(defaultOwnerPkHash, api.Mul(hasDefaultHidden, hiddenOwnerPkHash))

	api.AssertIsEqual(api.Mul(hasRingHidden, hasDefaultHidden), 0)
	for _, published := range publishedOutputOwnerPkHashes {
		assertZeroWhen(api, hasRingHidden, api.IsZero(api.Sub(published, hiddenOwnerPkHash)))
	}
}
