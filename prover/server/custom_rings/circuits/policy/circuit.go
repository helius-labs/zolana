// Requires the transaction to satisfy the ring's policy in the same
// proof that checks audit encryption and binds the supplied entry roots.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	base "zolana/prover/custom_rings/circuits/base"
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
	Salt          [16]frontend.Variable

	Inputs  [NInputs]UtxoWires
	Outputs [NOutputs]UtxoWires
	// Exactly one flag selects count index+1.
	// Tags preserve the witness names stored in the proving key.
	InputCountSelected  [NInputs]frontend.Variable  `gnark:"NInOneHot"`
	OutputCountSelected [NOutputs]frontend.Variable `gnark:"NOutOneHot"`

	AddressChain     frontend.Variable
	ExternalDataHash frontend.Variable
	// Folded last into the private transaction hash, as in SPP.
	PrivateTxBlinding frontend.Variable

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
	// Zero selects limits per transfer without a spend record.
	WindowSlots frontend.Variable
	Velocity    [NVelocityAssets]VelocityRowWires
	// Exactly one flag selects count index.
	VelocityCountSelected [NVelocityAssets + 1]frontend.Variable `gnark:"VelocityCountOneHot"`

	// The program selects roots from the configured entries tree's history.
	StateRoot frontend.Variable
	// The program limits nullifier root age with NULLIFIER_ROOT_WINDOW.
	NullifierRoot frontend.Variable
	// The raw id of the entries tree, every leaf and address hashes under it.
	EntriesTreeID frontend.Variable
	// The ring program id field, a change output stays in it.
	RingID frontend.Variable
	// The owner hash of the ring's namespace PDA, only spend record slots open to it.
	NamespaceOwnerHash frontend.Variable
	// The program derives the fixed window index, zero without a window.
	WindowIndex frontend.Variable
	// Set when an outflow exceeds its co-sign threshold, the program then demands the co-signer.
	ApprovalRequired frontend.Variable

	// Counter openings are required only within the predecessor's window.
	Record RecordWires

	// All rules and transaction slots share these list facts.
	ListFacts [NListFacts]ListFactWires `gnark:"Answers"`
}

type policyRail uint8

const (
	memberRail policyRail = iota
	delegateRail
)

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	chain, _, _ := c.constrainPolicyRail(api, memberRail)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// The rail is fixed in the compiled circuit, never selected by a witness.
func (c *CustomRingPolicyCircuit) constrainPolicyRail(api frontend.API, rail policyRail) ([]frontend.Variable, transactionContext, successorCounters) {
	// 1. Prove the audit encryption statement.
	elements := base.DefineAuditBlock(api, base.AuditBlockWires{
		PrivateTxHash:       c.PrivateTxHash,
		TxViewingSk:         c.TxViewingSk,
		EphSk:               c.EphSk,
		AuditorPk:           c.AuditorPk,
		Salt:                c.Salt,
		Outputs:             auditOutputs(api, c.Outputs),
		OutputCountSelected: c.OutputCountSelected,
	})
	// Both blocks share one BSB22 commitment.
	rangeChecker := rangecheck.New(api)

	// 2. Check the policy and reconstruct its commitment.
	checked := c.checkPolicy(api, rangeChecker)

	// 3. Bind policy subjects and amounts to the SPP transaction.
	recordEnabled := checked.velocity.windowEnabled
	if rail == delegateRail {
		recordEnabled = frontend.Variable(0)
	}
	txContext := c.constrainTransactionContext(api, rangeChecker, recordEnabled)
	c.constrainNamespace(api, txContext)

	// 4. Authenticate the shared list facts.
	listFacts := c.checkListFacts(api, rangeChecker)

	// 5. Require every applicable rule to pass.
	c.constrainRules(api, txContext, listFacts, checked.ruleEnabled, checked.inlineEnabled)

	var counters successorCounters
	if rail == delegateRail {
		api.AssertIsEqual(c.WindowIndex, 0)
		api.AssertIsEqual(c.ApprovalRequired, 0)
	} else {
		counters = c.constrainVelocity(api, rangeChecker, checked.velocity, txContext)
	}

	chain := append(elements[:],
		checked.hash, c.StateRoot, c.NullifierRoot, c.EntriesTreeID,
		c.RingID, c.NamespaceOwnerHash, c.WindowIndex, c.ApprovalRequired,
	)
	for _, fact := range listFacts {
		chain = append(chain, fact.revocationTarget)
	}
	return chain, txContext, counters
}
