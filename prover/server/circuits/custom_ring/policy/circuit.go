package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	base "zolana/prover/circuits/custom_ring/base"
	"zolana/prover/circuits/gadget"
)

// OwnerHash commits to the namespace serving ListId.
type SourceWires struct {
	ListId    frontend.Variable
	OwnerHash frontend.Variable
}

type CustomRingPolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
	AuditorPk     [65]frontend.Variable

	Inputs     [NIn]OpeningWires
	Outputs    [NOut]OpeningWires
	NInOneHot  [NIn]frontend.Variable
	NOutOneHot [NOut]frontend.Variable

	AddressChain     frontend.Variable
	ExternalDataHash frontend.Variable

	Sources           [NSources]SourceWires
	RuleCountOneHot   [NRules + 1]frontend.Variable
	Rules             [NRules]RuleWires
	InlineAssets      [NInlineAssets]frontend.Variable
	InlineLimits      [NInlineAssets]frontend.Variable
	InlineCountOneHot [NInlineAssets + 1]frontend.Variable

	StateRoot     frontend.Variable
	NullifierRoot frontend.Variable

	Answers [NAnswers]AnswerWires
}

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	elements := base.DefineAuditBlock(api, base.AuditBlockWires{
		PrivateTxHash: c.PrivateTxHash,
		TxViewingSk:   c.TxViewingSk,
		EphSk:         c.EphSk,
		AuditorPk:     c.AuditorPk,
	})
	// Both blocks share one BSB22 commitment.
	checker := rangecheck.New(api)

	slots := c.checkOpenings(api, checker)
	policyHash, ruleEnabled, inlineEnabled := c.checkPolicy(api, checker)
	answers := c.checkAnswers(api, checker)
	c.evaluate(api, slots, answers, ruleEnabled, inlineEnabled)

	// Bind the policy and supplied entry roots after the audit inputs.
	chain := append(elements[:], policyHash, c.StateRoot, c.NullifierRoot)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
