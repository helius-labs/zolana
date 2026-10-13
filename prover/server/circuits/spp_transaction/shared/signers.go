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

// Ed25519Signers resolves the zero owner-tag sentinel to the shared Ed25519
// owner whose signature the circuit verifies. Non-zero tags remain Solana
// signer identities authorized by the runtime.
func Ed25519Signers(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorizedEddsa Signers,
	ed25519PkHash frontend.Variable,
) Signers {
	signers := make(Signers, len(inputs))
	hasEd25519Input := frontend.Variable(0)
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		isEd25519 := api.IsZero(ownerPkHashes[i])
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		pkHash := api.Select(isEd25519, ed25519PkHash, ownerPkHashes[i])
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		AssertWhen(
			api,
			api.Mul(carriesContent, api.Sub(1, isEd25519)),
			authorizedEddsa.Contains(api, ownerPkHashes[i]),
		)
		hasEd25519Input = api.Add(hasEd25519Input, api.Mul(carriesContent, isEd25519))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	// This rail mixes in-circuit Ed25519 and runtime signers; it is not an
	// alternative all-runtime selector. All-runtime transactions use the ring rail.
	api.AssertIsDifferent(hasEd25519Input, 0)
	return signers
}

// AssertDefaultEd25519Owner publishes the shared Ed25519 identity iff at least
// one spent Ed25519 UTXO belongs to the default ring. Ring-only Ed25519 inputs
// keep the shared owner private and require the public field to be zero.
//
// A ring Ed25519 input is an anonymous spend, so the shared identity must stay
// out of the transaction's public data: no default-ring Ed25519 input may force
// it into defaultEd25519OwnerPkHash, no published output owner tag may equal
// it, and no public signer may equal it. The identity is the Solana-tagged
// hash of the key, the same value SPP publishes for a runtime signer of that
// key (for example a wallet that also pays the fee), so the signer vector,
// payer included, is checked as well. Publishing the identity without a ring
// Ed25519 input is allowed; moving a default-ring UTXO into the ring names the
// depositor, not a ring spender.
//
// Address slots count as neither. An address has RingProgramID 0
// (checkAddress), so treating it as a default-ring input would publish the
// identity of a ring spender who creates an address in the same proof and
// would forbid that combination. Creating an address spends nothing, so it
// does not force the identity into public data; an Ed25519 address-only proof
// publishes zero.
func AssertDefaultEd25519Owner(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	publishedOutputOwnerPkHashes []frontend.Variable,
	publicSigners Signers,
	ed25519PkHash frontend.Variable,
	defaultEd25519OwnerPkHash frontend.Variable,
) {
	hasDefaultEd25519 := frontend.Variable(0)
	hasRingEd25519 := frontend.Variable(0)
	for i, in := range inputs {
		isEd25519 := api.IsZero(ownerPkHashes[i])
		isDefaultRing := api.IsZero(in.Utxo.RingProgramID)
		realEd25519 := api.Mul(in.isUtxo(api), isEd25519)
		hasDefaultEd25519 = api.Add(hasDefaultEd25519, api.Mul(realEd25519, isDefaultRing))
		hasRingEd25519 = api.Add(hasRingEd25519, api.Mul(realEd25519, api.Sub(1, isDefaultRing)))
	}
	hasDefaultEd25519 = api.Sub(1, api.IsZero(hasDefaultEd25519))
	hasRingEd25519 = api.Sub(1, api.IsZero(hasRingEd25519))
	api.AssertIsEqual(defaultEd25519OwnerPkHash, api.Mul(hasDefaultEd25519, ed25519PkHash))

	api.AssertIsEqual(api.Mul(hasRingEd25519, hasDefaultEd25519), 0)
	for _, published := range publishedOutputOwnerPkHashes {
		assertZeroWhen(api, hasRingEd25519, api.IsZero(api.Sub(published, ed25519PkHash)))
	}
	for _, signer := range publicSigners {
		assertZeroWhen(api, hasRingEd25519, api.IsZero(api.Sub(signer, ed25519PkHash)))
	}
}
