// Package transfer holds the universal custom ring circuit: package audit's
// verifiable-encryption statement, unchanged, folded with a policy block that
// decides one SPP transaction against a compiled rule table and an answers
// array of policy entry proofs.
//
// The circuit has exactly one public input, PublicInputHash, the Poseidon hash
// chain over these eleven elements in this exact order:
//
//  1. private_tx_hash    -- recomputed from the witnessed openings
//  2. tx_viewing_pk_lo   -- audit block, see package audit
//  3. tx_viewing_pk_hi
//  4. auditor_pk_lo
//  5. auditor_pk_hi
//  6. eph_pk_lo
//  7. eph_pk_hi
//  8. ct_hash
//  9. policy_hash        -- recomputed, binds the per-list namespace owner map
//  10. state_root        -- the SPP roots the entry proofs open against
//  11. nullifier_root
//
// The Rust mirror of element 9 is program-libs/ring-policy, table hashing in
// rule_table.rs over the entry derivation in entry.rs. Element 1 comes from the
// SPP transaction circuit, elements 10 and 11 from the tree account, and
// elements 2 to 8 keep the mirror named in package audit.
package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	audit "zolana/prover/circuits/custom_ring"
	"zolana/prover/circuits/gadget"
)

// SourceWires is bound to the on-chain source map through the policy hash
// alone.
type SourceWires struct {
	ListId    frontend.Variable
	OwnerHash frontend.Variable
}

type Circuit struct {
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
	LenOneHot         [NRules + 1]frontend.Variable
	Rules             [NRules]RuleWires
	InlineAssets      [NInlineAssets]frontend.Variable
	InlineCountOneHot [NInlineAssets + 1]frontend.Variable

	StateRoot     frontend.Variable
	NullifierRoot frontend.Variable

	Answers [NAnswers]RuleAnswerWires
}

func (c *Circuit) Define(api frontend.API) error {
	elements := audit.DefineBlock(api, audit.BlockWires{
		PrivateTxHash: c.PrivateTxHash,
		TxViewingSk:   c.TxViewingSk,
		EphSk:         c.EphSk,
		AuditorPk:     c.AuditorPk,
	})
	// Reusing the range checker the audit block instantiated keeps the folded
	// circuit at one BSB22 commitment.
	checker := rangecheck.New(api)

	slots := c.defineOpenings(api, checker)
	policyHash, enabled := c.definePolicy(api, checker)
	c.evaluate(api, slots, c.defineAnswers(api, checker), enabled)

	chain := append(elements[:], policyHash, c.StateRoot, c.NullifierRoot)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
