package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// PoolEntryWires is one policy record proof, placing the record or its absence
// under both SPP roots.
type PoolEntryWires struct {
	Enabled      frontend.Variable
	Mode         frontend.Variable
	Kind         frontend.Variable
	Member       frontend.Variable
	PayloadHash  frontend.Variable
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

type poolView struct {
	enabled frontend.Variable
	mode    frontend.Variable
	kind    frontend.Variable
	member  frontend.Variable
}

type records struct {
	ownerHash     frontend.Variable
	stateRoot     frontend.Variable
	nullifierRoot frontend.Variable
}

func (c *Circuit) definePool(api frontend.API, checker frontend.Rangechecker) [NPool]poolView {
	ring := records{
		ownerHash:     c.RecordsOwnerHash,
		stateRoot:     c.StateRoot,
		nullifierRoot: c.NullifierRoot,
	}
	var out [NPool]poolView
	for i, entry := range c.Pool {
		out[i] = entry.define(api, checker, ring)
	}
	return out
}

// define mirrors the derivations in ring_policy::record.
func (w PoolEntryWires) define(api frontend.API, checker frontend.Rangechecker, ring records) poolView {
	api.AssertIsBoolean(w.Enabled)
	checker.Check(w.Kind, 8)
	checker.Check(w.Version, 64)
	// Neither the zero padding member nor the inline kind 0 names a record.
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.Member))
	shared.AssertWhen(api, w.Enabled, nonZero(api, w.Kind))

	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, w.Enabled, api.Add(isPresent, isAbsent))

	absent := api.Mul(w.Enabled, isAbsent)
	noAddress := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchNoAddress))
	cleared := api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchCleared))
	shared.AssertWhen(api, absent, api.Add(noAddress, cleared))

	seed := gadget.PoseidonHash(api, []frontend.Variable{policyAddressDomain, w.Kind, w.Member})
	address := gadget.PoseidonHash(api, []frontend.Variable{
		addressUtxoHash(api, ring.ownerHash, seed),
		seed,
		0,
	})
	dataHash := gadget.PoseidonHash(api, []frontend.Variable{
		policyRecordDomain,
		address,
		w.Kind,
		w.Member,
		w.State,
		w.Version,
		w.PayloadHash,
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
		B:    api.Select(clearedBranch, RecordStateCleared, RecordStateActive),
	})

	// Target the address to prove no record was ever created, the nullifier to
	// prove the opened record is unspent.
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

	return poolView{
		enabled: w.Enabled,
		mode:    w.Mode,
		kind:    w.Kind,
		member:  w.Member,
	}
}

// addressUtxoHash is the record's address slot commitment, blinded by the seed.
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
