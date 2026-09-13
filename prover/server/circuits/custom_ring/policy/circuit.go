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
	// Zero disables velocity, else the fixed window length in slots.
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
	// The program derives slot / WindowSlots, zero without velocity.
	WindowIndex frontend.Variable
	// Set when an outflow exceeds its co-sign threshold, the program then demands the co-signer.
	ApprovalRequired frontend.Variable

	// The sender's spend record, opened only when velocity is on.
	Record RecordWires

	// All rules and transaction slots share these list facts.
	ListFacts [NListFacts]ListFactWires `gnark:"Answers"`
}

func (c *CustomRingPolicyCircuit) Define(api frontend.API) error {
	chain, _ := c.constrainPolicy(api)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// constrainPolicy returns the public-input chain unhashed for the compressed
// variant to extend before the final hash.
func (c *CustomRingPolicyCircuit) constrainPolicy(api frontend.API) ([]frontend.Variable, transactionContext) {
	return c.constrainPolicyRail(api, false)
}

// The rail is fixed in the compiled circuit, never selected by a witness.
func (c *CustomRingPolicyCircuit) constrainPolicyRail(api frontend.API, delegate bool) ([]frontend.Variable, transactionContext) {
	// 1. Prove the audit encryption statement.
	elements := base.DefineAuditBlock(api, base.AuditBlockWires{
		PrivateTxHash: c.PrivateTxHash,
		TxViewingSk:   c.TxViewingSk,
		EphSk:         c.EphSk,
		AuditorPk:     c.AuditorPk,
	})
	// Both blocks share one BSB22 commitment.
	rangeChecker := rangecheck.New(api)

	// 2. Check the policy and reconstruct its commitment.
	policyHash, ruleEnabled, inlineEnabled, velocity := c.checkPolicy(api, rangeChecker)

	// 3. Bind policy subjects and amounts to the SPP transaction.
	recordOn := velocity.on
	if delegate {
		recordOn = frontend.Variable(0)
	}
	txContext := c.constrainTransactionContext(api, rangeChecker, recordOn)
	c.constrainNamespace(api, txContext)

	// 4. Authenticate the shared list facts.
	listFacts := c.checkListFacts(api, rangeChecker)

	// 5. Require every applicable rule to pass.
	c.constrainRules(api, txContext, listFacts, ruleEnabled, inlineEnabled)

	// 6. Spend the sender's record into its successor within the caps.
	if delegate {
		api.AssertIsEqual(c.WindowIndex, 0)
		api.AssertIsEqual(c.ApprovalRequired, 0)
	} else {
		c.constrainVelocity(api, rangeChecker, velocity, txContext)
	}

	// 7. Bind the policy, the supplied entry roots and the window after the
	// audit inputs.
	chain := append(elements[:],
		policyHash, c.StateRoot, c.NullifierRoot, c.EntriesTreeID,
		c.RingID, c.NamespaceOwnerHash, c.WindowIndex, c.ApprovalRequired,
	)
	return chain, txContext
}
