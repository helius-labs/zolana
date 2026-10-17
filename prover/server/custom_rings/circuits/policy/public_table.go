package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// PublicTable is already public in PolicyConfig. A verifier supplies these
// values from the program-owned account, never from untrusted instruction data.
// Direct binding avoids rehashing the full table inside every transfer proof.
type PublicTable struct {
	Hash                       frontend.Variable
	Sources                    [NSources]SourceWires
	Rules                      [NRules]frontend.Variable
	PolicyLen                  frontend.Variable
	InlineAssets, InlineLimits [NInlineAssets]frontend.Variable
	InlineCount                frontend.Variable
	Limits                     [NOutflowLimits]OutflowLimitWires
	LimitCount                 frontend.Variable
}

type PublicTableTwoByThreeCircuit struct {
	Circuit  TwoByThreeCircuit
	Table    PublicTable `gnark:",public"`
	Registry [2]registry.SparseSubtree
	TreeHash frontend.Variable `gnark:",public"`
}

func (c *PublicTableTwoByThreeCircuit) Define(api frontend.API) error {
	p := &c.Circuit.Policy
	p.RegistryWitness = &c.Registry
	p.PublicTreeHash = c.TreeHash
	p.PublicPolicyHash = c.Table.Hash
	bindPublicTable(api, p, c.Table)
	return c.Circuit.Define(api)
}

func bindPublicTable(api frontend.API, p *CustomRingPolicyCircuit, table PublicTable) {
	api.AssertIsEqual(p.PolicyLen, table.PolicyLen)
	api.AssertIsEqual(p.InlineCount, table.InlineCount)
	api.AssertIsEqual(p.LimitCount, table.LimitCount)
	for i, source := range table.Sources {
		api.AssertIsEqual(p.Sources[i].ListId, source.ListId)
		api.AssertIsEqual(p.Sources[i].Registry, source.Registry)
	}
	for i, rule := range table.Rules {
		api.AssertIsEqual(p.Rules[i], rule)
	}
	for i, asset := range table.InlineAssets {
		api.AssertIsEqual(p.InlineAssets[i], asset)
		api.AssertIsEqual(p.InlineLimits[i], table.InlineLimits[i])
	}
	for i, limit := range table.Limits {
		api.AssertIsEqual(p.Limits[i].Asset, limit.Asset)
		api.AssertIsEqual(p.Limits[i].Cap, limit.Cap)
		api.AssertIsEqual(p.Limits[i].CosignAbove, limit.CosignAbove)
	}
}
