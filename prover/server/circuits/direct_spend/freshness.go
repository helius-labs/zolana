package directspend

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

type NonInclusion struct {
	Low   frontend.Variable
	Next  frontend.Variable
	Index frontend.Variable
	Path  []frontend.Variable
}

type Freshness struct {
	TreeID     frontend.Variable
	Root       frontend.Variable
	Count      frontend.Variable
	Nullifiers []frontend.Variable
	Witnesses  []NonInclusion
}

type FreshnessCircuit struct {
	Freshness
	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewFreshness(n int) *FreshnessCircuit {
	c := &FreshnessCircuit{Freshness: Freshness{
		Nullifiers: make([]frontend.Variable, n), Witnesses: make([]NonInclusion, n),
	}}
	for i := range c.Witnesses {
		c.Witnesses[i].Path = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return c
}

func (c *FreshnessCircuit) Define(api frontend.API) error {
	if err := c.Freshness.constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.fields(api)))
	return nil
}

func (f *Freshness) constrain(api frontend.API) error {
	return f.constrainWithCompressor(api, nil)
}

func (f *Freshness) constrainWithCompressor(api frontend.API, compressor *gadget.GKRCompressor) error {
	if len(f.Nullifiers) == 0 || len(f.Nullifiers) > MaxInputs || len(f.Witnesses) != len(f.Nullifiers) {
		return fmt.Errorf("direct spend: invalid freshness shape")
	}
	api.ToBinary(f.TreeID, 16)
	api.AssertIsDifferent(f.Count, 0)
	count, previous := frontend.Variable(0), frontend.Variable(1)
	for i, witness := range f.Witnesses {
		if len(witness.Path) != transaction.NullifierTreeHeight {
			return fmt.Errorf("direct spend: invalid nullifier path %d", i)
		}
		active := api.Sub(1, api.IsZero(f.Nullifiers[i]))
		api.AssertIsEqual(api.Mul(active, api.Sub(1, previous)), 0)
		previous = active
		count = api.Add(count, active)
		root := merkleRoot(api, gadget.IndexedLeafHash(api, witness.Low, witness.Next), witness.Index, witness.Path, compressor)
		api.AssertIsEqual(api.Mul(active, api.Sub(root, f.Root)), 0)
		abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
			Lo: api.Select(active, witness.Low, 0), Mid: api.Select(active, f.Nullifiers[i], 1),
			Hi: api.Select(active, witness.Next, 2),
		})
	}
	api.AssertIsEqual(f.Count, count)
	return nil
}

func (f *Freshness) fields(api frontend.API) []frontend.Variable {
	return []frontend.Variable{FreshnessDomain, f.TreeID, f.Root, f.Count, gadget.HashChain4(api, f.Nullifiers)}
}
