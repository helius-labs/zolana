package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// ShapeWires uses the settlement circuit capacities. The witnessed counts select
// the live prefix. These slices never change the legacy circuit's wire layout.
type ShapeWires struct {
	Inputs          []UtxoWires
	Outputs         []OutputWires
	Subjects        []registry.MemberOpening
	ForeignSubjects []registry.MemberOpening
}

func (c *CustomRingPolicyCircuit) compact() bool { return c.FixedInputs != 0 || c.Dynamic != nil }

func (c *CustomRingPolicyCircuit) wires() ([]UtxoWires, []OutputWires, []registry.MemberOpening, []registry.MemberOpening) {
	if c.Dynamic != nil {
		return c.Dynamic.Inputs, c.Dynamic.Outputs, c.Dynamic.Subjects, c.Dynamic.ForeignSubjects
	}
	return c.Inputs[:], c.Outputs[:], c.Subjects[:], c.ForeignSubjects[:]
}

// ShapeCircuit retains every policy rule and auditor disclosure. Its verifying
// key pins settlement capacities, privacy mode and registry authentication.
type ShapeCircuit struct {
	Policy   CustomRingPolicyCircuit
	Table    PublicTable `gnark:",public"`
	Registry []registry.SparseSubtree
	TreeHash frontend.Variable `gnark:",public"`
	ShapeWires
	Anonymous bool `gnark:"-"`
	Delegate  bool `gnark:"-"`
}

func NewShapeCircuit(inputs, outputs int, anonymous, delegate, subtree bool) *ShapeCircuit {
	if inputs < 1 || inputs > 16 || outputs < 1 || outputs > 4 || anonymous && inputs > 4 || anonymous && delegate {
		panic("unsupported custom-ring shape capacities")
	}
	c := &ShapeCircuit{Anonymous: anonymous, Delegate: delegate,
		ShapeWires: ShapeWires{Inputs: make([]UtxoWires, inputs), Outputs: make([]OutputWires, outputs),
			Subjects: make([]registry.MemberOpening, inputs+2*outputs), ForeignSubjects: make([]registry.MemberOpening, inputs+2*outputs)}}
	if subtree {
		c.Registry = make([]registry.SparseSubtree, 2)
	}
	return c
}

func (c *ShapeCircuit) Define(api frontend.API) error {
	p := &c.Policy
	p.Dynamic = &c.ShapeWires
	p.FixedMode = 1
	if c.Anonymous {
		p.FixedMode = 2
	}
	if len(c.Registry) == 2 {
		p.RegistryWitness = (*[2]registry.SparseSubtree)(c.Registry)
	}
	p.PublicTreeHash, p.PublicPolicyHash = c.TreeHash, c.Table.Hash
	bindPublicTable(api, p, c.Table)
	rail := memberRail
	if c.Delegate {
		rail = delegateRail
	}
	api.AssertIsEqual(p.PublicInputHash, gadget.HashChain(api, p.constrain(api, rail)))
	return nil
}
