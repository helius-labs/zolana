package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/records"
)

type Entry struct {
	Own     records.QuadOpening
	Curator records.QuadOpening
}

type subjectView struct {
	// onList[i] is set when the subject is on list i+1 in the registry serving the list.
	onList [NSources]frontend.Variable
	// escrowKey is the own record's escrow key, zero for an absent member.
	escrowKey frontend.Variable
}

type subjects struct {
	sender         subjectView
	owners, assets []subjectView
}

// resolveSubjects opens the sender, every UTXO output's owner and, under an asset rule, every UTXO output's asset.
func (p *Policy) resolveSubjects(api frontend.API, t tableView, sender frontend.Variable, outputs []utxoView) subjects {
	s := subjects{
		sender: p.resolve(api, t.sources, p.SenderEntry, 1, sender),
		owners: make([]subjectView, len(outputs)),
		assets: make([]subjectView, len(outputs)),
	}
	for o, out := range outputs {
		s.owners[o] = p.resolve(api, t.sources, p.OwnerEntries[o], out.utxo, out.ownerPkHash)
		s.assets[o] = p.resolve(api, t.sources, p.AssetEntries[o], api.Mul(out.utxo, t.assetRules), out.asset)
	}
	return s
}

// resolve opens member in the own registry, and in the curator registry when a list is foreign, while cond holds.
func (p *Policy) resolve(api frontend.API, sources sourceView, e Entry, cond, member frontend.Variable) subjectView {
	// 1. The member's record, or the low record proving it absent, lies under own_root.
	own, escrowKey := e.Own.Resolve(api, cond, p.OwnRoot, member)
	// 2. The same holds under curator_root whenever a list reads from the curator registry.
	curator, _ := e.Curator.Resolve(api, api.Mul(cond, sources.anyForeign), p.CuratorRoot, member)
	// 3. A record's list bitmap splits bit per list, bit i marks list i+1.
	ownBits, curatorBits := api.ToBinary(own, records.ListBits), api.ToBinary(curator, records.ListBits)
	view := subjectView{escrowKey: escrowKey}
	for i := range view.onList {
		view.onList[i] = api.Select(sources.foreign[i], curatorBits[i], ownBits[i])
	}
	return view
}

// assertEscrow requires under key escrow every UTXO output's owner record to escrow the output's nullifier key.
func (p *Policy) assertEscrow(api frontend.API, keyEscrow frontend.Variable, owners []subjectView, outputs []utxoView) {
	for o, out := range outputs {
		escrowed := api.Mul(out.utxo, keyEscrow)
		key := records.EscrowKey(api, out.nullifierPk, p.Outputs[o].CtHash)
		// The owner's record escrows Poseidon(nullifier_pk, ct_hash), an absent owner resolves zero and never matches.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: owners[o].escrowKey, B: key})
	}
}
