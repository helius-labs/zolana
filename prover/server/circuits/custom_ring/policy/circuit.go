// Requires the transaction to satisfy the ring's policy in the same
// proof that checks audit encryption and binds the supplied entry roots.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	base "zolana/prover/circuits/custom_ring/base"
	"zolana/prover/circuits/gadget"
)

// SourceWires binds a list to its namespace owner through the policy hash.
type SourceWires struct {
	ListId    frontend.Variable
	OwnerHash frontend.Variable
}

// CustomRingPolicyCircuit proves that transaction subjects satisfy the ring's
// committed rules.
type CustomRingPolicyCircuit struct {
	// The verifier supplies a hash of the audit inputs, policy and accepted
	// roots.
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
	AuditorPk     [65]frontend.Variable

	Inputs  [NInputs]OpeningWires
	Outputs [NOutputs]OpeningWires
	// Exactly one flag selects count index+1.
	// Tags preserve the witness names stored in the proving key.
	InputCountSelected  [NInputs]frontend.Variable  `gnark:"NInOneHot"`
	OutputCountSelected [NOutputs]frontend.Variable `gnark:"NOutOneHot"`

	AddressChain     frontend.Variable
	ExternalDataHash frontend.Variable

	// Every rule uses the same list-to-namespace map.
	Sources [NSources]SourceWires
	// Exactly one flag selects count index.
	RuleCountSelected [NRules + 1]frontend.Variable `gnark:"RuleCountOneHot"`
	Rules             [NRules]RuleWires
	// Inline rules check asset membership, per-asset guards use matching
	// limits.
	InlineAssets [NInlineAssets]frontend.Variable
	InlineLimits [NInlineAssets]frontend.Variable
	// Exactly one flag selects count index.
	InlineAssetCountSelected [NInlineAssets + 1]frontend.Variable `gnark:"InlineCountOneHot"`

	// The program selects roots from the configured entries tree's history.
	StateRoot frontend.Variable
	// The program limits nullifier root age with NULLIFIER_ROOT_WINDOW.
	NullifierRoot frontend.Variable

	// All rules and transaction slots share these list facts.
	ListFacts [NListFacts]ListFactWires `gnark:"Answers"`
}

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	// 1. Prove the audit encryption statement.
	elements := base.DefineAuditBlock(api, base.AuditBlockWires{
		PrivateTxHash: c.PrivateTxHash,
		TxViewingSk:   c.TxViewingSk,
		EphSk:         c.EphSk,
		AuditorPk:     c.AuditorPk,
	})
	// Both blocks share one BSB22 commitment.
	checker := rangecheck.New(api)

	// 2. Bind policy subjects and amounts to the SPP transaction.
	txContext := c.checkOpenings(api, checker)

	// 3. Check the policy and reconstruct its commitment.
	policyHash, ruleEnabled, inlineEnabled := c.checkPolicy(api, checker)

	// 4. Authenticate the shared list facts.
	listFacts := c.checkListFacts(api, checker)

	// 5. Require every applicable rule to pass.
	c.evaluate(api, txContext, listFacts, ruleEnabled, inlineEnabled)

	// 6. Bind the policy and supplied entry roots after the audit inputs.
	chain := append(elements[:], policyHash, c.StateRoot, c.NullifierRoot)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
