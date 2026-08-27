package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// RuleAnswerWires is one policy entry proof, placing the entry or its absence
// under both SPP roots.
type RuleAnswerWires struct {
	Enabled      frontend.Variable
	Mode         frontend.Variable
	ListId         frontend.Variable
	Member       frontend.Variable
	ContentHash  frontend.Variable
	Version      frontend.Variable
	State        frontend.Variable
	AbsentBranch frontend.Variable
	Low          frontend.Variable
	Next         frontend.Variable

	NfPathElements [shared.NullifierTreeHeight]frontend.Variable
	NfPathIndex    frontend.Variable

	StatePathElements [shared.StateTreeHeight]frontend.Variable
	StatePathIndex    frontend.Variable
}

type answerView struct {
	enabled frontend.Variable
	mode    frontend.Variable
	listId    frontend.Variable
	member  frontend.Variable
}

type entries struct {
	ownerHash     frontend.Variable
	stateRoot     frontend.Variable
	nullifierRoot frontend.Variable
}

func (c *Circuit) defineAnswers(api frontend.API, checker frontend.Rangechecker) [NAnswers]answerView {
	var out [NAnswers]answerView
	for i, entry := range c.Answers {
		out[i] = entry.define(api, checker, entries{
			ownerHash:     resolveOwner(api, c.Sources, entry),
			stateRoot:     c.StateRoot,
			nullifierRoot: c.NullifierRoot,
		})
	}
	return out
}

// define mirrors the derivations in ring_policy::entry.
func (w RuleAnswerWires) define(api frontend.API, checker frontend.Rangechecker, ring entries) answerView {
	api.AssertIsBoolean(w.Enabled)
	checker.Check(w.ListId, 8)
	checker.Check(w.Version, 64)
	// Neither the zero padding member nor the inline listId 0 names an entry,
	// and listId 0 could only resolve against empty source slots.
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.Member))
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.ListId))

	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, w.Enabled, api.Add(isPresent, isAbsent))

	absent := api.Mul(w.Enabled, isAbsent)
	noAddress := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchNoAddress))
	cleared := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchCleared))
	shared.AssertWhen(api, absent, api.Add(noAddress, cleared))

	seed := gadget.PoseidonHash(api, []frontend.Variable{policyAddressDomain, w.ListId, w.Member})
	address := gadget.PoseidonHash(api, []frontend.Variable{
		addressUtxoHash(api, ring.ownerHash, seed),
		seed,
		0,
	})
	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		policyRecordDomain,
		address,
		w.ListId,
		w.Member,
		w.State,
		w.Version,
		w.ContentHash,
	})
	// The version doubles as the blinding, keeping a re-added member off an old
	// commitment.
	utxoHash := gadget.PoseidonHash(api, []frontend.Variable{
		shared.UtxoDomain,
		solAssetField,
		0,
		dataHash,
		emptyRingHash,
		gadget.PoseidonHash(api, []frontend.Variable{ring.ownerHash, w.Version}),
	})
	nullifier := gadget.PoseidonHash(api, []frontend.Variable{utxoHash, w.Version, 0})

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
		B:    ring.stateRoot,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: needInclusion,
		A:    w.State,
		B:    api.Select(clearedBranch, EntryStateCleared, EntryStateActive),
	})

	// Target the address to prove no entry was ever created, the nullifier to
	// prove the opened entry is unspent.
	target := api.Select(api.Mul(absent, noAddress), address, nullifier)
	nullifierRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   gadget.IndexedLeafHash(api, w.Low, w.Next),
		Index:  api.ToBinary(w.NfPathIndex, shared.NullifierTreeHeight),
		Path:   w.NfPathElements[:],
		Height: shared.NullifierTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: w.Enabled,
		A:    nullifierRoot,
		B:    ring.nullifierRoot,
	})
	low := gadget.CanonicalLimbs(api, w.Low)
	mid := gadget.CanonicalLimbs(api, target)
	high := gadget.CanonicalLimbs(api, w.Next)
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, low, mid))
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, mid, high))

	return answerView{
		enabled: w.Enabled,
		mode:    w.Mode,
		listId:    w.ListId,
		member:  w.Member,
	}
}

// addressUtxoHash is the entry's address slot commitment, blinded by the seed.
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
