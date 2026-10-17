// Package policy proves that a ring transaction satisfies the policy the ring commits to.
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

	NIn               frontend.Variable
	NOut              frontend.Variable
	Inputs            [NInputs]UtxoWires
	Outputs           [NOutputs]OutputWires
	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable

	// Slot i is empty or serves list i+1, from the curator registry it names or the ring's own.
	Sources   [NSources]SourceWires
	PolicyLen frontend.Variable
	// Each rule packs its fields as ring_policy::Rule::encoded does.
	Rules        [NRules]frontend.Variable
	InlineAssets [NInlineAssets]frontend.Variable
	InlineLimits [NInlineAssets]frontend.Variable
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
	Subjects [NSubjects]registry.MemberOpening
	// ForeignRoot is the curator registry the sources name, zero without one.
	ForeignRoot     frontend.Variable
	ForeignSubjects [NSubjects]registry.MemberOpening
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
	checked := c.checkPolicy(api, rc)
	tx := c.constrainTransaction(api, rc)
	c.constrainNamespace(api, tx)
	subjects := c.resolveSubjects(api, tx, checked.sources)
	c.constrainRules(api, tx, subjects, checked)
	if rail == delegateRail {
		api.AssertIsEqual(c.ApprovalRequired, 0)
		api.AssertIsEqual(c.KeyEscrow, 1)
		// The delegate rail never serves an anonymous ring.
		api.AssertIsEqual(c.Anonymous, 0)
	} else {
		c.constrainLimits(api, checked.limits, tx)
	}
	c.constrainEscrow(api, tx, subjects)

	audit := c.Audit.Define(api, rc, c.auditTx(tx))
	return append(audit[:], checked.hash, shared.TreeSlotsHashChain(api, c.TreeSlots[:]), c.AddressTreeID,
		c.RingID, c.NamespaceOwnerHash, c.ApprovalRequired, c.KeyEscrow, c.MemberRegistryRoot, c.ForeignRoot)
}
