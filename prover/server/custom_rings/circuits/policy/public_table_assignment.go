package policy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// AssignPublicTable derives the additional witness from the existing full
// Merkle openings. It is called only after the request decoder fills all wires.
// Public fields are recomputed by the verifier from its own policy account.
func AssignPublicTable(p *CustomRingPolicyCircuit, anonymous, delegate bool) (*PublicTableTwoByThreeCircuit, error) {
	integer := func(v frontend.Variable) *big.Int {
		switch v := v.(type) {
		case *big.Int:
			return new(big.Int).Set(v)
		case int:
			return big.NewInt(int64(v))
		case uint8:
			return new(big.Int).SetUint64(uint64(v))
		case uint32:
			return new(big.Int).SetUint64(uint64(v))
		case uint64:
			return new(big.Int).SetUint64(v)
		default:
			panic(fmt.Sprintf("unassigned policy wire %T", v))
		}
	}
	count := func(v frontend.Variable, max int) (int, error) {
		n := integer(v)
		if !n.IsUint64() || n.Uint64() > uint64(max) {
			return 0, fmt.Errorf("policy count outside capacity")
		}
		return int(n.Uint64()), nil
	}
	inputs, outputs, own, foreignRecords := p.wires()
	nIn, err := count(p.NIn, len(inputs))
	if err != nil {
		return nil, err
	}
	nOut, err := count(p.NOut, len(outputs))
	if err != nil {
		return nil, err
	}
	mode := 0
	if anonymous {
		mode = 1
	}
	if nIn < 1 || nOut < 1 || p.Dynamic == nil && (nIn != 2 || nOut != 3) || integer(p.Anonymous).Cmp(big.NewInt(int64(mode))) != 0 || anonymous && delegate {
		return nil, fmt.Errorf("policy requires its pinned shape and mode")
	}
	ruleCount, err := count(p.PolicyLen, NRules)
	if err != nil {
		return nil, err
	}
	inlineCount, err := count(p.InlineCount, NInlineAssets)
	if err != nil {
		return nil, err
	}
	limitCount, err := count(p.LimitCount, NOutflowLimits)
	if err != nil {
		return nil, err
	}
	fields := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	foreign := false
	for _, s := range p.Sources {
		fields = append(fields, integer(s.ListId), integer(s.Registry))
		foreign = foreign || integer(s.Registry).Sign() != 0
	}
	fields = append(fields, integer(p.PolicyLen), integer(p.InlineCount), integer(p.LimitCount))
	assetRules := false
	for _, r := range p.Rules[:ruleCount] {
		v := integer(r)
		fields = append(fields, v)
		assetRules = assetRules || v.Uint64()&255 == SubjectAsset
	}
	for i := 0; i < inlineCount; i++ {
		fields = append(fields, integer(p.InlineAssets[i]), integer(p.InlineLimits[i]))
	}
	for _, l := range p.Limits[:limitCount] {
		fields = append(fields, integer(l.Asset), integer(l.Cap), integer(l.CosignAbove))
	}
	hash := fields[0]
	for _, f := range fields[1:] {
		hash, err = poseidon.Hash([]*big.Int{hash, f})
		if err != nil {
			return nil, err
		}
	}
	treeHashes := make([]*big.Int, len(p.TreeSlots))
	for i, s := range p.TreeSlots {
		treeHashes[i], err = poseidon.Hash([]*big.Int{integer(s.ID), integer(s.UtxoRoot), integer(s.NullifierRoot)})
		if err != nil {
			return nil, err
		}
	}
	treeHash, err := transcript.RightHashChain(treeHashes)
	if err != nil {
		return nil, err
	}
	w := &PublicTableTwoByThreeCircuit{
		Circuit: TwoByThreeCircuit{Policy: *p, Anonymous: anonymous, Delegate: delegate},
		Table: PublicTable{Hash: hash, Sources: p.Sources, Rules: p.Rules, PolicyLen: p.PolicyLen,
			InlineAssets: p.InlineAssets, InlineLimits: p.InlineLimits, InlineCount: p.InlineCount,
			Limits: p.Limits, LimitCount: p.LimitCount}, TreeHash: treeHash,
	}
	if p.Dynamic != nil && p.RegistrySubtreeDepth == 0 {
		return w, nil
	}
	subjects := make(map[int]*big.Int)
	for i, input := range inputs[:nIn] {
		if integer(input.Domain).Cmp(big.NewInt(shared.UtxoDomain)) == 0 {
			subjects[i] = integer(input.OwnerPkHash)
		}
	}
	for i, output := range outputs[:nOut] {
		if integer(output.Domain).Cmp(big.NewInt(shared.UtxoDomain)) != 0 {
			continue
		}
		subjects[len(inputs)+i] = integer(output.OwnerPkHash)
		if assetRules && integer(output.Asset).Sign() != 0 {
			subjects[len(inputs)+len(outputs)+i] = integer(output.Asset)
		}
	}
	for registryIndex, records := range [2][]registry.MemberOpening{own, foreignRecords} {
		var openings []registry.SparseOpening
		if registryIndex == 0 || foreign {
			for i, record := range records {
				member, active := subjects[i]
				if !active {
					continue
				}
				next, lists, escrow := integer(record.Next), integer(record.Lists), integer(record.EscrowKey)
				if integer(record.Present).Sign() == 0 {
					member, next, lists, escrow = integer(record.LowMember), integer(record.LowNext), integer(record.LowLists), integer(record.LowEscrow)
				}
				leaf, err := poseidon.Hash([]*big.Int{member, next, lists, escrow})
				if err != nil {
					return nil, err
				}
				index := integer(record.Index)
				if !index.IsUint64() {
					return nil, fmt.Errorf("registry index outside capacity")
				}
				opening := registry.SparseOpening{Index: index.Uint64(), Leaf: leaf, Path: make([]big.Int, registry.Height)}
				for j, v := range record.Path {
					opening.Path[j].Set(integer(v))
				}
				openings = append(openings, opening)
			}
		}
		w.Registry[registryIndex], err = registry.BuildSparseSubtree(openings)
		if err != nil {
			return nil, err
		}
	}
	return w, nil
}
