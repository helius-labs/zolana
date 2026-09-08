package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

type AnswerWires struct {
	Enabled            frontend.Variable
	Mode               frontend.Variable
	ListId             frontend.Variable
	Member             frontend.Variable
	ContentHash        frontend.Variable
	Version            frontend.Variable
	State              frontend.Variable
	AbsentBranch       frontend.Variable
	NullifierLowValue  frontend.Variable
	NullifierNextValue frontend.Variable

	NullifierLowPathElements [shared.NullifierTreeHeight]frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	StatePathElements [shared.StateTreeHeight]frontend.Variable
	StatePathIndex    frontend.Variable
}

type answerView struct {
	enabled frontend.Variable
	mode    frontend.Variable
	listId  frontend.Variable
	member  frontend.Variable
}

type entryProofInputs struct {
	ownerHash     frontend.Variable
	stateRoot     frontend.Variable
	nullifierRoot frontend.Variable
}

func (c *CustomRingPolicyCircuit) checkAnswers(api frontend.API, checker frontend.Rangechecker) [NAnswers]answerView {
	var out [NAnswers]answerView
	for i, answer := range c.Answers {
		out[i] = answer.check(api, checker, entryProofInputs{
			ownerHash:     resolveSourceOwner(api, c.Sources, answer),
			stateRoot:     c.StateRoot,
			nullifierRoot: c.NullifierRoot,
		})
	}
	return out
}

func (w AnswerWires) check(api frontend.API, checker frontend.Rangechecker, proof entryProofInputs) answerView {
	// Enabled answers claim a nonzero list member.
	api.AssertIsBoolean(w.Enabled)
	checker.Check(w.ListId, 8)
	checker.Check(w.Version, 64)
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.Member))
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.ListId))

	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, w.Enabled, api.Add(isPresent, isAbsent))

	absent := api.Mul(w.Enabled, isAbsent)
	neverCreated := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchNeverCreated))
	cleared := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchCleared))
	shared.AssertWhen(api, absent, api.Add(neverCreated, cleared))

	// The source, list and member fix the entry address.
	seed := gadget.PoseidonHash(api, []frontend.Variable{policyAddressDomain, w.ListId, w.Member})
	address := gadget.PoseidonHash(api, []frontend.Variable{
		addressUtxoHash(api, proof.ownerHash, seed),
		seed,
		0,
	})
	// The entry commitment binds its state, version and content.
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
		gadget.PoseidonHash(api, []frontend.Variable{proof.ownerHash, w.Version}),
	})
	nullifier := gadget.PoseidonHash(api, []frontend.Variable{utxoHash, w.Version, 0})

	// Present and cleared entries require state inclusion.
	clearedBranch := api.Mul(absent, cleared)
	needInclusion := api.Add(api.Mul(w.Enabled, isPresent), clearedBranch)
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  api.ToBinary(w.StatePathIndex, shared.StateTreeHeight),
		Path:   w.StatePathElements[:],
		Height: shared.StateTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: needInclusion,
		A:    stateRoot,
		B:    proof.stateRoot,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: needInclusion,
		A:    w.State,
		B:    api.Select(clearedBranch, EntryStateCleared, EntryStateActive),
	})

	// Present and cleared entries must be unspent at NullifierRoot.
	target := api.Select(api.Mul(absent, neverCreated), address, nullifier)
	nullifierRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   gadget.IndexedLeafHash(api, w.NullifierLowValue, w.NullifierNextValue),
		Index:  api.ToBinary(w.NullifierLowPathIndex, shared.NullifierTreeHeight),
		Path:   w.NullifierLowPathElements[:],
		Height: shared.NullifierTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: w.Enabled,
		A:    nullifierRoot,
		B:    proof.nullifierRoot,
	})
	// Full-field ordering requires canonical limbs.
	lowLimbs := gadget.CanonicalLimbs(api, w.NullifierLowValue)
	targetLimbs := gadget.CanonicalLimbs(api, target)
	nextLimbs := gadget.CanonicalLimbs(api, w.NullifierNextValue)
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, lowLimbs, targetLimbs))
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, targetLimbs, nextLimbs))

	return answerView{
		enabled: w.Enabled,
		mode:    w.Mode,
		listId:  w.ListId,
		member:  w.Member,
	}
}

// The seed blinds the address slot.
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
