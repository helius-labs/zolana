package shared

import (
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// The functions below generalize HiddenOwnerSigners and
// AssertDefaultHiddenOwner to several hidden owners. Each hidden input names
// its owner by a private index, so the public data does not say which hidden
// owner spent which input. A single-owner circuit keeps the original
// functions, which compile to the committed constraint system.

// HiddenOwnerSelectors returns, per input, one bit per hidden owner that is
// set for the owner indices[i] names. Every index must name an owner, so the
// bits of each input sum to one; a non-hidden input names owner 0 and its
// bits are ignored.
func HiddenOwnerSelectors(api frontend.API, indices []frontend.Variable, nOwners int) [][]frontend.Variable {
	selectors := make([][]frontend.Variable, len(indices))
	for i, index := range indices {
		bits := make([]frontend.Variable, nOwners)
		sum := frontend.Variable(0)
		for j := range bits {
			bits[j] = api.IsZero(api.Sub(index, j))
			sum = api.Add(sum, bits[j])
		}
		api.AssertIsEqual(sum, 1)
		selectors[i] = bits
	}
	return selectors
}

// selectHiddenOwner returns the identity the selector bits pick.
func selectHiddenOwner(api frontend.API, bits, owners []frontend.Variable) frontend.Variable {
	identity := frontend.Variable(0)
	for j, owner := range owners {
		identity = api.Add(identity, api.Mul(bits[j], owner))
	}
	return identity
}

// AssertDistinctHiddenOwners requires the hidden owners to differ from each
// other and from every public signer. The hidden identities share the Solana
// identity hash, so a repeat would let one signature stand in for another
// owner's.
func AssertDistinctHiddenOwners(api frontend.API, owners []frontend.Variable, publicSigners Signers) {
	for j, owner := range owners {
		for _, signer := range publicSigners {
			api.AssertIsDifferent(signer, owner)
		}
		for _, other := range owners[j+1:] {
			api.AssertIsDifferent(owner, other)
		}
	}
}

// HiddenOwnersSigners resolves the zero owner-tag sentinel to the hidden owner
// the input's selector names. Non-zero tags remain Solana signer identities.
// Every hidden owner must own at least one content-bearing input, so a
// verified signature always stands for a spender.
func HiddenOwnersSigners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	authorizedEddsa Signers,
	hiddenOwners []frontend.Variable,
	selectors [][]frontend.Variable,
) Signers {
	signers := make(Signers, len(inputs))
	spends := make([]frontend.Variable, len(hiddenOwners))
	for j := range spends {
		spends[j] = frontend.Variable(0)
	}
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		isHidden := api.IsZero(ownerPkHashes[i])
		assertZeroWhen(api, api.Sub(1, carriesContent), ownerPkHashes[i])
		hiddenOwner := selectHiddenOwner(api, selectors[i], hiddenOwners)
		pkHash := api.Select(isHidden, hiddenOwner, ownerPkHashes[i])
		AssertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		AssertWhen(
			api,
			api.Mul(carriesContent, api.Sub(1, isHidden)),
			authorizedEddsa.Contains(api, ownerPkHashes[i]),
		)
		hiddenSpend := api.Mul(carriesContent, isHidden)
		for j, bit := range selectors[i] {
			spends[j] = api.Add(spends[j], api.Mul(hiddenSpend, bit))
		}
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	for _, count := range spends {
		api.AssertIsDifferent(count, 0)
	}
	return signers
}

// AssertDefaultHiddenOwners applies AssertDefaultHiddenOwner to each hidden
// owner and returns the identities it publishes: owner j's identity when one
// of its spent hidden-owner UTXOs belongs to the default ring, zero
// otherwise. defaultOwnerPkHash commits to them as RightHashChain in owner
// order, which for one owner is the identity itself.
//
// An owner with a ring hidden input is an anonymous spender, so it may not
// also spend a default-ring hidden input and no published output owner tag may
// equal its identity. The rule is per owner: one owner's default-ring spend
// publishes only that owner.
func AssertDefaultHiddenOwners(
	api frontend.API,
	inputs []Input,
	ownerPkHashes []frontend.Variable,
	selectors [][]frontend.Variable,
	publishedOutputOwnerPkHashes []frontend.Variable,
	hiddenOwners []frontend.Variable,
	defaultOwnerPkHash frontend.Variable,
) []frontend.Variable {
	published := make([]frontend.Variable, len(hiddenOwners))
	for j, owner := range hiddenOwners {
		hasDefaultHidden := frontend.Variable(0)
		hasRingHidden := frontend.Variable(0)
		for i, in := range inputs {
			isHidden := api.IsZero(ownerPkHashes[i])
			isDefaultRing := api.IsZero(in.Utxo.RingProgramID)
			ownedHidden := api.Mul(in.isUtxo(api), isHidden, selectors[i][j])
			hasDefaultHidden = api.Add(hasDefaultHidden, api.Mul(ownedHidden, isDefaultRing))
			hasRingHidden = api.Add(hasRingHidden, api.Mul(ownedHidden, api.Sub(1, isDefaultRing)))
		}
		hasDefaultHidden = api.Sub(1, api.IsZero(hasDefaultHidden))
		hasRingHidden = api.Sub(1, api.IsZero(hasRingHidden))
		api.AssertIsEqual(api.Mul(hasRingHidden, hasDefaultHidden), 0)
		for _, tag := range publishedOutputOwnerPkHashes {
			assertZeroWhen(api, hasRingHidden, api.IsZero(api.Sub(tag, owner)))
		}
		published[j] = api.Mul(hasDefaultHidden, owner)
	}
	api.AssertIsEqual(defaultOwnerPkHash, gadget.RightHashChain(api, published))
	return published
}
