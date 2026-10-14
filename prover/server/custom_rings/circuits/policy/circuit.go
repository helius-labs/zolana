// Package policy proves that a ring transaction satisfies the policy the ring commits to.
package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties: the audit statement holds, every enabled rule passes for each live subject on list facts
// that open at the slot roots, and windowed outflow stays within each cap, with output keys escrowed.

type CustomRingPolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	base.Audit

	NIn               frontend.Variable
	NOut              frontend.Variable
	Inputs            [NInputs]UtxoWires
	Outputs           [NOutputs]OutputWires
	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable

	// Slot i is empty or serves list i+1.
	Sources   [NSources]SourceWires
	PolicyLen frontend.Variable
	// Each rule packs its fields as ring_policy::Rule::encoded does.
	Rules        [NRules]frontend.Variable
	InlineAssets [NInlineAssets]frontend.Variable
	InlineLimits [NInlineAssets]frontend.Variable
	InlineCount  frontend.Variable
	// Zero caps each transfer alone, without a spend record.
	WindowSlots   frontend.Variable
	Velocity      [NVelocityAssets]VelocityRowWires
	VelocityCount frontend.Variable

	TreeSlots          [shared.InputTrees]shared.TreeSlot
	AddressTreeID      frontend.Variable
	RingID             frontend.Variable
	NamespaceOwnerHash frontend.Variable
	WindowIndex        frontend.Variable
	ApprovalRequired   frontend.Variable
	KeyEscrow          frontend.Variable
	KeyRegistryRoot    frontend.Variable
	Record             RecordWires
	ListFacts          [NListFacts]ListFactWires
}

type SourceWires struct {
	ListId    frontend.Variable
	OwnerHash frontend.Variable
}

type policyRail uint8

const (
	memberRail policyRail = iota
	delegateRail
)

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	chain, _ := c.constrain(api, memberRail)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// The compiled circuit fixes the rail, no witness selects it.
func (c *CustomRingPolicyCircuit) constrain(api frontend.API, rail policyRail) ([]frontend.Variable, successorCounters) {
	rc := rangecheck.New(api)
	checked := c.checkPolicy(api, rc)
	recordEnabled := checked.velocity.windowEnabled
	if rail == delegateRail {
		recordEnabled = 0
	}
	tx := c.constrainTransaction(api, rc, recordEnabled)
	c.constrainNamespace(api, tx)
	facts, factSlots := c.checkListFacts(api, rc)
	c.constrainRules(api, tx, facts, checked)
	var counters successorCounters
	if rail == delegateRail {
		api.AssertIsEqual(c.WindowIndex, 0)
		api.AssertIsEqual(c.ApprovalRequired, 0)
		api.AssertIsEqual(c.KeyEscrow, 1)
	} else {
		counters = c.constrainVelocity(api, rc, checked.velocity, tx)
	}
	c.constrainOutputKeys(api, tx)

	var openings [NOutputs]base.AuditOutputWires
	var hashes [NOutputs]frontend.Variable
	for i, output := range tx.outputs {
		openings[i], hashes[i] = output.opening, output.hash
	}
	audit := c.Audit.Define(api, rc, openings, hashes, tx.nOut)
	chain := append(audit[:], checked.hash, shared.TreeSlotsHashChain(api, c.TreeSlots[:]), c.AddressTreeID,
		c.RingID, c.NamespaceOwnerHash, c.WindowIndex, c.ApprovalRequired, c.KeyEscrow, c.KeyRegistryRoot, factSlots)
	for _, fact := range facts {
		chain = append(chain, fact.revocationTarget)
	}
	return chain, counters
}
