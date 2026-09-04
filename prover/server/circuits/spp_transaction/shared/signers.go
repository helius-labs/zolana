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

// WithoutPayer drops the payer, leaving the deduplicated owner signers and the
// zero padding. The signer vector always carries the payer first, so it is
// never empty.
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

// EddsaOnlySigners returns the private owner identities of content-bearing
// inputs. Dummy inputs contribute zero.
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

// AuthorizedEddsaInputOwners resolves the private per-input owner identities and
// requires every content-bearing input to be authorized by the unified signer
// vector. The vector contains the payer first, then appended Solana signers.
func AuthorizedEddsaInputOwners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorized Signers,
) Signers {
	owners := EddsaOnlySigners(api, inputs, ownerPkHashes)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		AssertWhen(api, carriesContent, authorized.Contains(api, ownerPkHashes[i]))
	}
	return owners
}

// P256Signers resolves the zero owner-tag sentinel to the shared P256 owner.
// Non-zero tags remain Solana signer identities.
func P256Signers(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorizedEddsa Signers,
	p256PkHash frontend.Variable,
	p256SignatureValid frontend.Variable,
) Signers {
	signers := make(Signers, len(inputs))
	hasP256Input := frontend.Variable(0)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		isP256 := api.IsZero(ownerPkHashes[i])
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		pkHash := api.Select(isP256, p256PkHash, ownerPkHashes[i])
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		AssertWhen(api, api.Mul(carriesContent, isP256), p256SignatureValid)
		AssertWhen(
			api,
			api.Mul(carriesContent, api.Sub(1, isP256)),
			authorizedEddsa.Contains(api, ownerPkHashes[i]),
		)
		hasP256Input = api.Add(hasP256Input, api.Mul(carriesContent, isP256))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	// RingP256 is the mixed P256/Ed25519 rail, not an alternative all-Ed25519
	// selector. All-Ed25519 transactions use RingEddsa.
	api.AssertIsDifferent(hasP256Input, 0)
	return signers
}

// AssertDefaultP256Owner publishes the shared P256 identity iff at least one
// real P256 UTXO/address belongs to the default ring. Ring-only P256 inputs keep
// the shared owner private and require the public field to be zero.
//
// A ring P256 input is an anonymous spend, so the shared identity must stay out
// of the transaction's public data: no default-ring P256 input may force it
// into defaultP256OwnerPkHash, and no published output owner tag may equal it.
// Publishing the identity without a ring P256 input is allowed; moving a
// default-ring P256 UTXO into the ring names the depositor, not a ring spender.
func AssertDefaultP256Owner(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	publishedOutputOwnerPkHashes []frontend.Variable,
	p256PkHash frontend.Variable,
	defaultP256OwnerPkHash frontend.Variable,
) {
	hasDefaultP256 := frontend.Variable(0)
	hasRingP256 := frontend.Variable(0)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		isP256 := api.IsZero(ownerPkHashes[i])
		isDefaultRing := api.IsZero(in.Utxo.RingProgramID)
		realP256 := api.Mul(carriesContent, isP256)
		hasDefaultP256 = api.Add(hasDefaultP256, api.Mul(realP256, isDefaultRing))
		hasRingP256 = api.Add(hasRingP256, api.Mul(realP256, api.Sub(1, isDefaultRing)))
	}
	hasDefaultP256 = api.Sub(1, api.IsZero(hasDefaultP256))
	hasRingP256 = api.Sub(1, api.IsZero(hasRingP256))
	api.AssertIsEqual(defaultP256OwnerPkHash, api.Mul(hasDefaultP256, p256PkHash))

	api.AssertIsEqual(api.Mul(hasRingP256, hasDefaultP256), 0)
	for _, published := range publishedOutputOwnerPkHashes {
		assertZeroWhen(api, hasRingP256, api.IsZero(api.Sub(published, p256PkHash)))
	}
}
