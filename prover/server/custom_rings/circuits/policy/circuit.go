package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// Properties: the audit statement holds, every enabled rule passes for each live subject on the
// lists its member record carries, and the transfer's outflow stays within each cap, with every
// output owner's key escrowed in the record when the ring escrows keys.

type CustomRingPolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	base.Audit
	// Compile-time capacities for a specialized key. Zero retains the general circuit.
	FixedInputs, FixedOutputs int         `gnark:"-"`
	Dynamic                   *ShapeWires `gnark:"-"`
	ShortOrdinaryAudit        bool        `gnark:"-"`
	// FixedMode is 0 for a witnessed mode, 1 for ordinary, 2 for anonymous.
	FixedMode            int `gnark:"-"`
	RegistrySubtreeDepth int `gnark:"-"`
	// Set only by a circuit that binds every table field to verifier inputs.
	PublicTreeHash   frontend.Variable          `gnark:"-"`
	PublicPolicyHash frontend.Variable          `gnark:"-"`
	RegistryWitness  *[2]registry.SparseSubtree `gnark:"-"`

	NIn               frontend.Variable
	NOut              frontend.Variable
	Inputs            [NInputs]UtxoWires    `shape:"dynamic"`
	Outputs           [NOutputs]OutputWires `shape:"dynamic"`
	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable

	// Slot i is empty or serves list i+1, from the curator registry it names or the ring's own.
	Sources   [NSources]SourceWires
	PolicyLen frontend.Variable
	// Each rule packs its fields as ring_policy::Rule::encoded does.
	Rules [NRules]frontend.Variable
	// Historical wire names for mint-specific amount guards. Asset screening
	// uses member-registry lists, never this threshold table.
	InlineAssets [NAmountGuards]frontend.Variable
	InlineLimits [NAmountGuards]frontend.Variable
	InlineCount  frontend.Variable
	Limits       [NOutflowLimits]OutflowLimitWires
	LimitCount   frontend.Variable

	TreeSlots          [shared.InputTrees]shared.TreeSlot
	AddressTreeID      frontend.Variable
	RingID             frontend.Variable
	NamespaceOwnerHash frontend.Variable
	ApprovalRequired   frontend.Variable
	KeyEscrow          frontend.Variable

	MemberRegistryRoot frontend.Variable
	// Subjects open input owners, output owners, then output assets in the own registry.
	Subjects [NSubjects]registry.MemberOpening `shape:"dynamic"`
	// ForeignRoot is the curator registry the sources name, zero without one.
	ForeignRoot     frontend.Variable
	ForeignSubjects [NSubjects]registry.MemberOpening `shape:"dynamic"`
}

type SourceWires struct {
	ListId   frontend.Variable
	Registry frontend.Variable
}

type policyRail uint8

const (
	memberRail policyRail = iota
	delegateRail
)

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.constrain(api, memberRail)))
	return nil
}

// The compiled circuit fixes the rail, no witness selects it.
func (c *CustomRingPolicyCircuit) constrain(api frontend.API, rail policyRail) []frontend.Variable {
	rc := rangecheck.New(api)
	// 1. Pin the statement variant before pruning constant branches.
	if c.FixedInputs != 0 {
		api.AssertIsEqual(c.NIn, c.FixedInputs)
	}
	if c.FixedOutputs != 0 {
		api.AssertIsEqual(c.NOut, c.FixedOutputs)
	}
	auditWitness := c.Audit
	if c.FixedMode != 0 {
		mode := c.FixedMode - 1
		api.AssertIsEqual(c.Anonymous, mode)
		auditWitness.Anonymous = mode
	}
	// 2. Decode rules once. Reopen the same private transaction hash as SPP.
	checked := c.checkPolicy(api, rc)
	tx := c.constrainTransaction(api, rc)
	c.constrainNamespace(api, tx)
	// 3. Authenticate subjects before applying list rules and amount guards.
	subjects := c.resolveSubjects(api, tx, checked)
	c.constrainRules(api, tx, subjects, checked)
	// 4. The key fixes the rail. A witness cannot select the delegate exemption.
	if rail == delegateRail {
		api.AssertIsEqual(c.ApprovalRequired, 0)
		api.AssertIsEqual(c.KeyEscrow, 1)
		// The delegate rail never serves an anonymous ring.
		api.AssertIsEqual(c.Anonymous, 0)
	} else {
		c.constrainLimits(api, checked.limits, tx)
	}
	c.constrainEscrow(api, tx, subjects)

	// 5. Disclose the checked openings and bind every configuration dependency.
	audit := auditWitness.Define(api, rc, c.auditTx(tx))
	treeHash := c.PublicTreeHash
	if treeHash == nil {
		treeHash = shared.TreeSlotsHashChain(api, c.TreeSlots[:])
	}
	return append(audit[:], checked.hash, treeHash, c.AddressTreeID,
		c.RingID, c.NamespaceOwnerHash, c.ApprovalRequired, c.KeyEscrow, c.MemberRegistryRoot, c.ForeignRoot)
}
