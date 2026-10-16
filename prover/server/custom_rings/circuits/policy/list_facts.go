package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// ListFactWires claims a member present in or absent from a list at the roots of one tree slot.
type ListFactWires struct {
	Enabled  frontend.Variable
	TreeSlot frontend.Variable
	Mode     frontend.Variable
	ListId   frontend.Variable
	// Member is a subject's owner public key hash or asset.
	Member      frontend.Variable
	ContentHash frontend.Variable
	Version     frontend.Variable
	// The entry output's blinding, inclusion binds it.
	Blinding     frontend.Variable
	State        frontend.Variable
	AbsentBranch frontend.Variable
	// The lower leaf bounds the target in the nullifier tree.
	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements [shared.NullifierTreeHeight]frontend.Variable
	NullifierLowPathIndex    frontend.Variable
	StatePathElements        [shared.StateTreeHeight]frontend.Variable
	StatePathIndex           frontend.Variable
}

type listFact struct {
	enabled, mode, member, revocationTarget frontend.Variable
	// onList[i] is set for list i+1.
	onList []frontend.Variable
}

// checkListFacts authenticates every fact and packs each enabled fact's slot index.
func (c *CustomRingPolicyCircuit) checkListFacts(api frontend.API, rc frontend.Rangechecker) ([NListFacts]listFact, frontend.Variable) {
	var facts [NListFacts]listFact
	packed := frontend.Variable(0)
	for i, w := range c.ListFacts {
		slot := api.Mul(w.Enabled, w.TreeSlot)
		facts[i] = w.check(api, rc, c.sourceOwner(api, w), shared.SelectTreeSlot(api, slot, c.TreeSlots[:], true), c.AddressTreeID)
		packed = api.Add(packed, api.Mul(slot, 1<<(shared.TreeIndexBits*i)))
	}
	return facts, packed
}

func (w ListFactWires) check(api frontend.API, rc frontend.Rangechecker, owner frontend.Variable, tree shared.TreeSlot, addressTreeID frontend.Variable) listFact {
	api.AssertIsBoolean(w.Enabled)
	rc.Check(w.ListId, 8)
	rc.Check(w.Version, 64)
	shared.AssertWhen(api, w.Enabled, base.NonZero(api, w.Member))
	shared.AssertWhen(api, w.Enabled, base.NonZero(api, w.ListId))
	present, isAbsent := api.IsZero(api.Sub(w.Mode, ModePresent)), api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, w.Enabled, api.Add(present, isAbsent))
	absent := api.Mul(w.Enabled, isAbsent)
	unclaimed := api.Mul(absent, api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchUnclaimedAddress)))
	cleared := api.Mul(absent, api.IsZero(api.Sub(w.AbsentBranch, AbsentBranchCleared)))
	shared.AssertWhen(api, absent, api.Add(unclaimed, cleared))
	// Addresses live only in the address tree's nullifier tree.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: unclaimed, A: tree.ID, B: addressTreeID})

	seed := gadget.PoseidonHash(api, []frontend.Variable{policyAddressDomain, w.ListId, w.Member})
	address := entryAddress(api, owner, seed, addressTreeID)
	dataHash := gadget.PoseidonHash(api, []frontend.Variable{policyRecordDomain, address, w.ListId, w.Member, w.State, w.Version, w.ContentHash})
	utxoHash := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain: shared.UtxoDomain, Owner: owner, Asset: solAssetField, Amount: 0, Blinding: w.Blinding,
		DataHash: dataHash, RingDataHash: 0, RingProgramID: 0,
	}, tree.ID)
	nullifier := gadget.PoseidonHash(api, []frontend.Variable{utxoHash, w.Blinding, 0})

	// Present and cleared claims open the entry in the state tree.
	included := api.Add(api.Mul(w.Enabled, present), cleared)
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: utxoHash, Index: api.ToBinary(w.StatePathIndex, shared.StateTreeHeight),
		Path: w.StatePathElements[:], Height: shared.StateTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: included, A: stateRoot, B: tree.UtxoRoot})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: included, A: w.State, B: api.Select(cleared, EntryStateCleared, EntryStateActive)})

	// Absence of the address or of the entry's nullifier sits strictly between a lower leaf and its next value.
	target := api.Select(unclaimed, address, nullifier)
	nullifierRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: gadget.IndexedLeafHash(api, w.NullifierLowValue, w.NullifierNextValue), Index: api.ToBinary(w.NullifierLowPathIndex, shared.NullifierTreeHeight),
		Path: w.NullifierLowPathElements[:], Height: shared.NullifierTreeHeight,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: w.Enabled, A: nullifierRoot, B: tree.NullifierRoot})
	low, mid, next := gadget.CanonicalLimbs(api, w.NullifierLowValue), gadget.CanonicalLimbs(api, target), gadget.CanonicalLimbs(api, w.NullifierNextValue)
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, low, mid))
	shared.AssertWhen(api, w.Enabled, gadget.IsLessLimbs(api, mid, next))

	onList := make([]frontend.Variable, NSources)
	for i := range onList {
		onList[i] = api.IsZero(api.Sub(w.ListId, i+1))
	}
	return listFact{enabled: w.Enabled, mode: w.Mode, member: w.Member, revocationTarget: api.Mul(w.Enabled, target), onList: onList}
}

// entryAddress mirrors the ring_policy entry address, a nullifier of the address UTXO.
func entryAddress(api frontend.API, owner, seed, treeID frontend.Variable) frontend.Variable {
	utxo := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain: shared.AddressDomain, Owner: owner, Asset: 0, Amount: 0, Blinding: seed, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
	}, treeID)
	return gadget.PoseidonHash(api, []frontend.Variable{utxo, seed, 0})
}
