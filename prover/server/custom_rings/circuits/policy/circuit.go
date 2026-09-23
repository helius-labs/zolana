// Requires the transaction to satisfy the ring's policy in the same
// proof that checks audit encryption and binds the supplied entry roots.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/registry"
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

	// Any live root per slot, a revocation target PDA check covers queued nullifiers.
	TreeSlots [shared.InputTrees]shared.TreeSlot
	// Every list and spend record address hashes under it.
	AddressTreeID frontend.Variable
	// The ring program id field, a change output stays in it.
	RingID frontend.Variable
	// The owner hash of the ring's namespace PDA, only spend record slots open to it.
	NamespaceOwnerHash frontend.Variable
	// The program derives the fixed window index, zero without a window.
	WindowIndex frontend.Variable
	// Set when an outflow exceeds its co-sign threshold, the program then demands the co-signer.
	ApprovalRequired frontend.Variable
	// Set with the delegate, every new output key must be escrowed.
	KeyEscrow       frontend.Variable
	KeyRegistryRoot frontend.Variable
	OutputKeys      [NOutputs]registry.KeyOpening

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
	chain, _ := c.constrainPolicyRail(api, memberRail)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// The rail is fixed in the compiled circuit, never selected by a witness.
func (c *CustomRingPolicyCircuit) constrainPolicyRail(api frontend.API, rail policyRail) ([]frontend.Variable, successorCounters) {
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
	listFacts, revocationTreeIndexes := c.checkListFacts(api, rangeChecker)

	// 5. Require every applicable rule to pass.
	c.constrainRules(api, txContext, listFacts, checked.ruleEnabled, checked.inlineEnabled)

	var counters successorCounters
	if rail == delegateRail {
		api.AssertIsEqual(c.WindowIndex, 0)
		api.AssertIsEqual(c.ApprovalRequired, 0)
		api.AssertIsEqual(c.KeyEscrow, 1)
	} else {
		counters = c.constrainVelocity(api, rangeChecker, checked.velocity, txContext)
	}

	// 6. Require escrowed nullifier keys on new outputs.
	c.constrainOutputKeys(api, txContext)

	chain := append(elements[:],
		checked.hash, shared.TreeSlotsHashChain(api, c.TreeSlots[:]), c.AddressTreeID,
		c.RingID, c.NamespaceOwnerHash, c.WindowIndex, c.ApprovalRequired,
		c.KeyEscrow, c.KeyRegistryRoot, revocationTreeIndexes,
	)
	for _, fact := range listFacts {
		chain = append(chain, fact.revocationTarget)
	}
	return chain, counters
}
