package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

const (
	linkedGroupDomain  = "zolana:ring-policy:group:v1"
	linkedCoreDomain   = "zolana:ring-policy:core:v1"
	linkedEscrowDomain = "zolana:ring-policy:escrow:v1"
	linkedOutputDomain = "zolana:ring-policy:output:v1"
)

var linkedFactStarts = [4]int{0, 3, 6, 8}
var linkedFactCounts = [4]int{3, 3, 2, 2}

// bitRange checks each bit directly so linked proofs need no BSB22 commitment.
type bitRange struct{ api frontend.API }

// Check enforces the unsigned bound without a lookup commitment.
func (r bitRange) Check(value frontend.Variable, bits int) { r.api.ToBinary(value, bits) }

// FactSummaryWires is exactly the authenticated fact data consumed by policy
// evaluation and published revocation checks.
type FactSummaryWires struct {
	Enabled, TreeSlot, Mode, ListId, Member, RevocationTarget frontend.Variable
}

// LinkedFactGroupCircuit authenticates one fixed, ordered subset of facts at
// the transaction's tree roots. Its digest links these private facts to the
// core proof without revealing their members.
type LinkedFactGroupCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	PrivateTxHash   frontend.Variable
	GroupDigest     frontend.Variable
	LinkBlinding    frontend.Variable
	TreeSlots       [shared.InputTrees]shared.TreeSlot
	AddressTreeID   frontend.Variable
	Sources         [NSources]SourceWires
	Facts           []ListFactWires
	start           int
}

// NewLinkedFactGroup fixes each fact's global slot at circuit compilation.
func NewLinkedFactGroup(group int) *LinkedFactGroupCircuit {
	if group < 0 || group >= len(linkedFactStarts) {
		panic("invalid linked fact group")
	}
	return &LinkedFactGroupCircuit{start: linkedFactStarts[group], Facts: make([]ListFactWires, linkedFactCounts[group])}
}

// Define authenticates every selected fact and binds its hidden commitment.
func (c *LinkedFactGroupCircuit) Define(api frontend.API) error {
	group := -1
	for i, start := range linkedFactStarts {
		if start == c.start && len(c.Facts) == linkedFactCounts[i] {
			group = i
			break
		}
	}
	if group < 0 {
		return fmt.Errorf("invalid linked fact group shape")
	}
	// 1. Authenticate every fact under its selected state and nullifier roots.
	rc := bitRange{api}
	summaries := make([]FactSummaryWires, 0, len(c.Facts))
	owners := make([]frontend.Variable, 0, len(c.Facts))
	for _, fact := range c.Facts {
		slot := api.Mul(fact.Enabled, fact.TreeSlot)
		owner := resolveSourceOwner(api, c.Sources, fact)
		context := listFactContext{
			ownerHash:     owner,
			tree:          shared.SelectTreeSlot(api, slot, c.TreeSlots[:], true),
			addressTreeID: c.AddressTreeID,
		}
		checked := fact.check(api, rc, context)
		summary := FactSummaryWires{
			Enabled: checked.enabled, TreeSlot: fact.TreeSlot, Mode: checked.mode,
			ListId: checked.listId, Member: checked.member,
			RevocationTarget: checked.revocationTarget,
		}
		summaries = append(summaries, summary)
		owners = append(owners, owner)
	}

	// 2. Bind the ordered facts and the trusted roots to this transaction.
	digest := linkedGroupDigest(api, c.LinkBlinding, c.start, summaries, owners)
	api.AssertIsEqual(c.GroupDigest, digest)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{
		packedASCII(linkedGroupDomain), c.PrivateTxHash, c.start, digest,
		shared.TreeSlotsHashChain(api, c.TreeSlots[:]), c.AddressTreeID,
	}))
	return nil
}

// linkedGroupDigest commits to the ordered fact fields and source owners.
// The transaction blinding hides repeated or guessable fact summaries.
// Fixed group lengths and the group index prevent splice and reorder attacks.
func linkedGroupDigest(api frontend.API, blinding frontend.Variable, start int, facts []FactSummaryWires, owners []frontend.Variable) frontend.Variable {
	if len(facts) != len(owners) {
		panic("linked fact owners mismatch")
	}
	fields := make([]frontend.Variable, 0, 3+7*len(facts))
	fields = append(fields, packedASCII(linkedGroupDomain), blinding, start)
	for i, fact := range facts {
		enabled := fact.Enabled
		fields = append(fields, enabled,
			api.Mul(enabled, fact.TreeSlot), api.Mul(enabled, fact.Mode),
			api.Mul(enabled, fact.ListId), api.Mul(enabled, fact.Member),
			api.Mul(enabled, fact.RevocationTarget), api.Mul(enabled, owners[i]),
		)
	}
	// A fixed-width first block and one linked final block avoid
	// a separate hash for every fact without changing the committed fields.
	split := min(13, len(fields))
	hash := gadget.PoseidonHash(api, fields[:split])
	if split < len(fields) {
		hash = gadget.PoseidonHash(api, append([]frontend.Variable{hash}, fields[split:]...))
	}
	return hash
}

// LinkedPolicyCoreCircuit proves policy authorization using fact digests whose
// corresponding authentication proofs the program verifies in the same call.
// The embedded policy witness reuses the existing rule and transaction checks.
type LinkedPolicyCoreCircuit struct {
	Policy       CustomRingPolicyCircuit
	Facts        [NListFacts]FactSummaryWires
	GroupDigests [4]frontend.Variable
	OutputDigest frontend.Variable
}

// Define requires each authenticated fact group and escrow opening to describe
// this transaction before accepting its policy authorization.
func (c *LinkedPolicyCoreCircuit) Define(api frontend.API) error {
	// 1. Bind rule commitments and transaction subjects as the current policy
	// circuit does.
	p := &c.Policy
	rc := bitRange{api}
	checked := p.checkPolicy(api, rc)
	tx := p.constrainTransactionContext(api, rc, checked.velocity.windowEnabled)
	p.constrainNamespace(api, tx)

	// 2. Reconstruct each fixed group digest from the private fact summaries.
	var facts [NListFacts]listFact
	packedIndexes := frontend.Variable(0)
	for group, start := range linkedFactStarts {
		summaries := make([]FactSummaryWires, 0, linkedFactCounts[group])
		owners := make([]frontend.Variable, 0, linkedFactCounts[group])
		for i := start; i < start+linkedFactCounts[group]; i++ {
			fact := c.Facts[i]
			owner := resolveSourceOwner(api, p.Sources, ListFactWires{Enabled: fact.Enabled, ListId: fact.ListId})
			summaries = append(summaries, fact)
			owners = append(owners, owner)
			facts[i] = listFact{enabled: fact.Enabled, mode: fact.Mode, listId: fact.ListId,
				member: fact.Member, revocationTarget: api.Mul(fact.Enabled, fact.RevocationTarget)}
			packedIndexes = api.Add(packedIndexes, api.Mul(fact.Enabled, fact.TreeSlot, 1<<(shared.TreeIndexBits*i)))
		}
		api.AssertIsEqual(c.GroupDigests[group], linkedGroupDigest(api, p.PrivateTxBlinding, start, summaries, owners))
	}

	// 3. Enforce the same rule, velocity, and namespace obligations.
	p.constrainRules(api, tx, facts, checked.ruleEnabled, checked.inlineEnabled)
	p.constrainVelocity(api, rc, checked.velocity, tx)

	// 4. Link output keys to the escrow proof and bind every on-chain policy
	// field and revocation target to the core proof.
	api.AssertIsEqual(c.OutputDigest, linkedOutputDigest(api, p.PrivateTxBlinding, tx.outputs))
	chain := []frontend.Variable{
		packedASCII(linkedCoreDomain), p.PrivateTxHash, checked.hash,
		shared.TreeSlotsHashChain(api, p.TreeSlots[:]), p.AddressTreeID,
		p.RingID, p.NamespaceOwnerHash, p.WindowIndex, p.ApprovalRequired,
		p.KeyEscrow, p.KeyRegistryRoot, packedIndexes,
	}
	for _, fact := range facts {
		chain = append(chain, fact.revocationTarget)
	}
	chain = append(chain, c.GroupDigests[:]...)
	chain = append(chain, c.OutputDigest)
	api.AssertIsEqual(p.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// LinkedEscrowOutputWires opens only the output fields needed by the registry
// proof. The core proof commits to exactly these fields through OutputDigest.
type LinkedEscrowOutputWires struct{ OwnerPkHash, NullifierPk, Utxo frontend.Variable }

// LinkedEscrowCircuit proves every required output nullifier key is enrolled
// under the same registry root and transaction as the core proof.
type LinkedEscrowCircuit struct {
	PublicInputHash                                frontend.Variable `gnark:",public"`
	PrivateTxHash, OutputDigest, LinkBlinding      frontend.Variable
	NamespaceOwnerHash, KeyEscrow, KeyRegistryRoot frontend.Variable
	Outputs                                        [NOutputs]LinkedEscrowOutputWires
	OutputKeys                                     [NOutputs]registry.KeyOpening
}

// Define binds every required enrollment to the core proof's blinded outputs.
func (c *LinkedEscrowCircuit) Define(api frontend.API) error {
	// 1. Bind the exact output fields proven by the core transaction check.
	registry.AssertMode(api, c.KeyEscrow, c.KeyRegistryRoot)
	var outputs [NOutputs]utxoView
	for i, output := range c.Outputs {
		api.AssertIsBoolean(output.Utxo)
		owner := gadget.PoseidonHash(api, []frontend.Variable{output.OwnerPkHash, output.NullifierPk})
		outputs[i] = utxoView{ownerPkHash: output.OwnerPkHash, nullifierPk: output.NullifierPk, utxo: output.Utxo}

		// 2. Require enrollment for each selected non-namespace output.
		namespace := api.IsZero(api.Sub(owner, c.NamespaceOwnerHash))
		cond := api.Mul(output.Utxo, c.KeyEscrow, api.Sub(1, namespace))
		c.OutputKeys[i].AssertEscrowed(api, cond, c.KeyRegistryRoot, output.OwnerPkHash, output.NullifierPk)
	}
	api.AssertIsEqual(c.OutputDigest, linkedOutputDigest(api, c.LinkBlinding, outputs))

	// 3. Bind the registry statement to the core and auditor transaction.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{
		packedASCII(linkedEscrowDomain), c.PrivateTxHash, c.OutputDigest,
		c.NamespaceOwnerHash, c.KeyEscrow, c.KeyRegistryRoot,
	}))
	return nil
}

// linkedOutputDigest hides output owner and nullifier keys with the transaction
// blinding while binding their exact slots for the escrow proof.
func linkedOutputDigest(api frontend.API, blinding frontend.Variable, outputs [NOutputs]utxoView) frontend.Variable {
	chain := make([]frontend.Variable, 0, NOutputs+2)
	chain = append(chain, packedASCII(linkedOutputDomain), blinding)
	for i, output := range outputs {
		chain = append(chain, gadget.PoseidonHash(api, []frontend.Variable{
			i, output.utxo, api.Mul(output.utxo, output.ownerPkHash),
			api.Mul(output.utxo, output.nullifierPk),
		}))
	}
	return gadget.HashChain(api, chain)
}
