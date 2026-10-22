package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties:
// 1. The rules read the policy table the program validated and hashed into policy_hash.
// 2. The outputs are the ones SPP settles under the private_tx_hash its proof binds.
// 3. One sender, the owner signer of a confidential ring, the sender an anonymous ring's commitment hides, or the one member a delegate move spends.
// 4. Every enabled rule holds for the sender and for every live output owner and asset on the lists their records carry, unless an amount guard exempts it.
// 5. On the member key every limit row's outflow is never negative and within its cap, and approval_required is set exactly when one passes its co-sign bound.
// 6. Under key escrow every UTXO output's owner record escrows the output's nullifier key.

type MemberPolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	// Anonymous selects how Sender reads, the owner signer identity or the sender commitment.
	Anonymous        frontend.Variable
	ApprovalRequired frontend.Variable
	KeyEscrow        frontend.Variable
	Sender           frontend.Variable
	// InputChain stays opaque, SPP's single owner signer or the anonymous audit proof binds every input to the sender.
	InputChain frontend.Variable
	Policy
}

type DelegatePolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Inputs          []base.UtxoWires
	Policy
}

type Policy struct {
	PrivateTxHash frontend.Variable
	PolicyHash    frontend.Variable
	RingProgramID frontend.Variable
	OwnRoot       frontend.Variable
	CuratorRoot   frontend.Variable
	PublicAssets  [shared.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, a withdrawal enters as the field negation of its amount.
	PublicAmounts [shared.NPublicSlots]frontend.Variable
	Table

	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable
	Outputs           []OutputWires
	// Read on an anonymous ring and on the delegate key, free on a confidential ring.
	SenderPkHash frontend.Variable

	SenderEntry Entry
	// OwnerEntries[o] and AssetEntries[o] open output o's owner and asset.
	OwnerEntries []Entry
	AssetEntries []Entry
}

type railValues struct {
	// anonymous is the member key's mode bit, absent from the delegate statement.
	anonymous                           []frontend.Variable
	approvalRequired, keyEscrow, sender frontend.Variable
}

var delegateRail = railValues{approvalRequired: 0, keyEscrow: 1, sender: 0}

func NewMemberPolicyCircuit(outputs int) (*MemberPolicyCircuit, error) {
	if !slices.Contains(MemberOutputs[:], outputs) {
		return nil, fmt.Errorf("policy: no member key for %d outputs", outputs)
	}
	return &MemberPolicyCircuit{Policy: newPolicy(outputs)}, nil
}

func NewDelegatePolicyCircuit(shape shared.Shape) (*DelegatePolicyCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, fmt.Errorf("policy: no delegate key, %w", err)
	}
	return &DelegatePolicyCircuit{Inputs: make([]base.UtxoWires, shape.NInputs), Policy: newPolicy(shape.NOutputs)}, nil
}

func newPolicy(outputs int) Policy {
	return Policy{
		Outputs:      make([]OutputWires, outputs),
		OwnerEntries: make([]Entry, outputs),
		AssetEntries: make([]Entry, outputs),
	}
}

func (c *MemberPolicyCircuit) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	cmp := c.comparator(rc)
	// 1. The rules read the table under policy_hash.
	t := c.Table.decode(api, rc, c.PolicyHash)
	// 2. The outputs open private_tx_hash beside the input chain SPP proves.
	outputs := c.openOutputs(api, c.InputChain)
	// 3. One sender, the owner signer, or on an anonymous ring the sender its commitment hides.
	sender := c.sender(api)
	// 4. The sender and every output's owner and asset are opened under own_root, and under curator_root when a list is foreign.
	s := c.resolveSubjects(api, t, sender, outputs)
	// 5. Every enabled rule holds for its subjects.
	c.assertRules(api, cmp, t, s, outputs)
	// 6. Every limit row bounds the outflow, approval_required says whether one passes its co-sign bound.
	c.assertApproval(api, c.constrainOutflow(api, cmp, t, sender, outputs))
	// 7. Under key escrow every output owner escrows the output's nullifier key.
	c.assertEscrow(api, c.KeyEscrow, s.owners, outputs)
	// 8. The one public input is the statement the program rebuilds.
	bindStatement(api, c.PublicInputHash, c.Statement())
	return nil
}

func (c *DelegatePolicyCircuit) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	cmp := c.comparator(rc)
	// 1. The rules read the table under policy_hash.
	t := c.Table.decode(api, rc, c.PolicyHash)
	// 2. The reopened inputs and the outputs open private_tx_hash.
	inputs, inputChain := openInputs(api, c.Inputs)
	outputs := c.openOutputs(api, inputChain)
	// 3. A delegate move spends one member, the sender.
	sender := c.sender(api, inputs)
	// 4. The sender and every output's owner and asset are opened under own_root, and under curator_root when a list is foreign.
	s := c.resolveSubjects(api, t, sender, outputs)
	// 5. Every enabled rule holds for its subjects.
	c.assertRules(api, cmp, t, s, outputs)
	// 6. The key fixes approval_required to 0, the program authorizes the configured delegate signer instead.
	// 7. The key fixes key_escrow to 1, every output owner escrows the output's nullifier key.
	c.assertEscrow(api, delegateRail.keyEscrow, s.owners, outputs)
	// 8. The one public input is the statement the program rebuilds, its sender value is 0.
	bindStatement(api, c.PublicInputHash, c.Statement())
	return nil
}

// validate checks the slices against the shape a constructor sizes, before a step indexes them.
func (p *Policy) validate() error {
	outputs, owners, assets := len(p.Outputs), len(p.OwnerEntries), len(p.AssetEntries)
	if outputs == 0 || owners != outputs || assets != outputs {
		return fmt.Errorf("policy: %d outputs need one owner and one asset entry each, got %d and %d", outputs, owners, assets)
	}
	return nil
}

func (c *DelegatePolicyCircuit) validate() error {
	if len(c.Inputs) == 0 {
		return fmt.Errorf("policy: a delegate move reopens at least one input")
	}
	return c.Policy.validate()
}

func (c *MemberPolicyCircuit) sender(api frontend.API) frontend.Variable {
	// 1. The anonymous audit proof opens the same commitment to the sender owning every input.
	gadget.AssertEqualWhen{Cond: c.Anonymous, A: c.Sender, B: base.SenderCommitment(api, c.SenderPkHash, c.PrivateTxBlinding)}.Assert(api)
	// 2. The select also holds the anonymous bit to 0 or 1, a fraction would blend the two senders.
	return api.Select(c.Anonymous, c.SenderPkHash, c.Sender)
}

func (c *DelegatePolicyCircuit) sender(api frontend.API, inputs []utxoView) frontend.Variable {
	// 1. Input 0 is a UTXO, the sender owns at least one spent input.
	api.AssertIsEqual(inputs[0].utxo, 1)
	for _, in := range inputs {
		// 2. Every UTXO input belongs to the sender.
		gadget.AssertEqualWhen{Cond: in.utxo, A: in.ownerPkHash, B: c.SenderPkHash}.Assert(api)
	}
	return c.SenderPkHash
}

func (c *MemberPolicyCircuit) assertApproval(api frontend.API, approval frontend.Variable) {
	// A transfer past a co-sign bound demands the co-signer, one within every bound claims no approval.
	api.AssertIsEqual(c.ApprovalRequired, approval)
}

func (c *MemberPolicyCircuit) rail() railValues {
	return railValues{
		anonymous:        []frontend.Variable{c.Anonymous},
		approvalRequired: c.ApprovalRequired,
		keyEscrow:        c.KeyEscrow,
		sender:           c.Sender,
	}
}

func (c *MemberPolicyCircuit) Statement() []frontend.Variable { return c.statement(c.rail()) }

func (c *DelegatePolicyCircuit) Statement() []frontend.Variable { return c.statement(delegateRail) }

// statement is the policy preimage, mirrored by PolicyStatement::elements in custom-rings/interface/src/statement.rs.
//
//	CRPO, private_tx_hash, policy_hash, ring_id, anonymous on the member key only, approval_required,
//	key_escrow, own_root, curator_root, sender, asset_k and amount_k per public slot
func (p *Policy) statement(rail railValues) []frontend.Variable {
	fields := []frontend.Variable{base.PolicyStatementDomain, p.PrivateTxHash, p.PolicyHash, p.RingProgramID}
	fields = append(fields, rail.anonymous...)
	fields = append(fields, rail.approvalRequired, rail.keyEscrow, p.OwnRoot, p.CuratorRoot, rail.sender)
	for k := range p.PublicAssets {
		fields = append(fields, p.PublicAssets[k], p.PublicAmounts[k])
	}
	return fields
}

func bindStatement(api frontend.API, publicInputHash frontend.Variable, statement []frontend.Variable) {
	// The one public input fixes every statement value the steps read to the ones the program rebuilds.
	api.AssertIsEqual(publicInputHash, gadget.HashChain4(api, statement))
}
