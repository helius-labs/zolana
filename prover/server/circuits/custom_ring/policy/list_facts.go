// Authenticates enabled claims of active membership or absence at the
// supplied tree roots for reuse across rules and transaction subjects.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// ListFactWires supplies a presence or absence claim and its proof witnesses.
type ListFactWires struct {
	// Disabled slots cannot cover rules.
	Enabled frontend.Variable
	Mode    frontend.Variable
	ListId  frontend.Variable
	// Member matches a subject's owner public key hash or asset.
	Member frontend.Variable
	// Entry fields reconstruct the stored commitment for Present and
	// Cleared proofs.
	ContentHash frontend.Variable
	Version     frontend.Variable
	State       frontend.Variable
	// AbsentBranch selects an unclaimed address or a cleared entry.
	AbsentBranch frontend.Variable
	// Lower-leaf bounds prove the target is absent from the nullifier tree.
	NullifierLowValue  frontend.Variable
	NullifierNextValue frontend.Variable

	NullifierLowPathElements [shared.NullifierTreeHeight]frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	// State paths authenticate Present and Cleared entries.
	StatePathElements [shared.StateTreeHeight]frontend.Variable
	StatePathIndex    frontend.Variable
}

// listFact supplies authenticated claims for evaluation when enabled.
type listFact struct {
	enabled frontend.Variable
	mode    frontend.Variable
	listId  frontend.Variable
	member  frontend.Variable
}

// listFactContext ties a list fact to its configured namespace owner and
// supplied tree roots.
type listFactContext struct {
	ownerHash     frontend.Variable
	stateRoot     frontend.Variable
	nullifierRoot frontend.Variable
}

// checkListFacts authenticates shared list facts before any rule can use them.
func (c *CustomRingPolicyCircuit) checkListFacts(api frontend.API, checker frontend.Rangechecker) [NListFacts]listFact {
	var out [NListFacts]listFact
	for i, fact := range c.ListFacts {
		// 1. Resolve the source namespace for the claimed list.
		context := listFactContext{
			ownerHash:     resolveSourceOwner(api, c.Sources, fact),
			stateRoot:     c.StateRoot,
			nullifierRoot: c.NullifierRoot,
		}

		// 2. Prove the list fact at the supplied roots.
		out[i] = fact.check(api, checker, context)
	}
	return out
}

// check authenticates an enabled claim for rule evaluation.
func (w ListFactWires) check(api frontend.API, checker frontend.Rangechecker, context listFactContext) listFact {
	// 1. Check the enabled claim, member and numeric bounds.
	api.AssertIsBoolean(w.Enabled)
	checker.Check(w.ListId, 8)
	checker.Check(w.Version, 64)
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.Member))
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.ListId))

	// 2. Require a valid list mode and absence branch.
	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, w.Enabled, api.Add(isPresent, isAbsent))

	absent := api.Mul(w.Enabled, isAbsent)
	unclaimed := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchUnclaimedAddress))
	cleared := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchCleared))
	shared.AssertWhen(api, absent, api.Add(unclaimed, cleared))

	// 3. Derive the entry address from its source, list and member.
	seed := gadget.PoseidonHash(api, []frontend.Variable{policyAddressDomain, w.ListId, w.Member})
	address := gadget.PoseidonHash(api, []frontend.Variable{
		addressUtxoHash(api, context.ownerHash, seed),
		seed,
		0,
	})

	// 4. Bind the entry state, version and content into its commitment and
	// nullifier.
	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		policyRecordDomain,
		address,
		w.ListId,
		w.Member,
		w.State,
		w.Version,
		w.ContentHash,
	})
	// The entry version is its blinding.
	utxoHash := gadget.PoseidonHash(api, []frontend.Variable{
		shared.UtxoDomain,
		solAssetField,
		0,
		dataHash,
		emptyRingHash,
		gadget.PoseidonHash(api, []frontend.Variable{context.ownerHash, w.Version}),
	})
	nullifier := gadget.PoseidonHash(api, []frontend.Variable{utxoHash, w.Version, 0})

	// 5. Require state inclusion for Present and Cleared claims.
	clearedBranch := api.Mul(absent, cleared)
	needsStateInclusion := api.Add(api.Mul(w.Enabled, isPresent), clearedBranch)
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  api.ToBinary(w.StatePathIndex, shared.StateTreeHeight),
		Path:   w.StatePathElements[:],
		Height: shared.StateTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: needsStateInclusion,
		A:    stateRoot,
		B:    context.stateRoot,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: needsStateInclusion,
		A:    w.State,
		B:    api.Select(clearedBranch, EntryStateCleared, EntryStateActive),
	})

	// 6. Select the unclaimed address or unspent entry nullifier for the
	// absence proof.
	nonInclusionTarget := api.Select(api.Mul(absent, unclaimed), address, nullifier)

	// 7. Authenticate the lower leaf at NullifierRoot.
	nullifierRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   gadget.IndexedLeafHash(api, w.NullifierLowValue, w.NullifierNextValue),
		Index:  api.ToBinary(w.NullifierLowPathIndex, shared.NullifierTreeHeight),
		Path:   w.NullifierLowPathElements[:],
		Height: shared.NullifierTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: w.Enabled,
		A:    nullifierRoot,
		B:    context.nullifierRoot,
	})

	// 8. Prove the target lies strictly between canonical lower and upper
	// bounds.
	lowLimbs := gadget.CanonicalLimbs(api, w.NullifierLowValue)
	targetLimbs := gadget.CanonicalLimbs(api, nonInclusionTarget)
	nextLimbs := gadget.CanonicalLimbs(api, w.NullifierNextValue)
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, lowLimbs, targetLimbs))
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, targetLimbs, nextLimbs))

	return listFact{
		enabled: w.Enabled,
		mode:    w.Mode,
		listId:  w.ListId,
		member:  w.Member,
	}
}

// addressUtxoHash binds the namespace owner and seed into the entry's address
// commitment.
func addressUtxoHash(api frontend.API, ownerHash, seed frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		shared.AddressDomain,
		0,
		0,
		0,
		emptyRingHash,
		gadget.PoseidonHash(api, []frontend.Variable{ownerHash, seed}),
	})
}
