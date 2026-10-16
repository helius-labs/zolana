package custom_ring

import (
	"crypto/ecdh"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func fi(v int64) Field    { return Field{big.NewInt(v)} }
func fb(v *big.Int) Field { return Field{v} }
func zeros(n int) []Field { return repeat(fi(0), n) }
func repeat(v Field, n int) []Field {
	out := make([]Field, n)
	for i := range out {
		out[i] = Field{new(big.Int).Set(v.Int)}
	}
	return out
}

// testScalar is a non zero P256 scalar below the group order.
func testScalar(seed byte) Bytes {
	out := make(Bytes, 32)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

func auditorKey(t *testing.T, seed byte) Bytes {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(testScalar(seed))
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().Bytes()
}

// decodeParams round trips params through the wire format, as the server reads them.
func decodeParams(t *testing.T, circuit common.CircuitType, params any) frontend.Circuit {
	t.Helper()
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := Decode(circuit, payload)
	if err != nil {
		t.Fatal(err)
	}
	return assignment
}

func zeroAuditOpening() AuditOpening {
	return AuditOpening{fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0)}
}

func zeroOpening() Opening {
	return Opening{fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0), fi(0)}
}

func zeroTreeSlots() TreeSlots {
	slots := make(TreeSlots, shared.InputTrees)
	for i := range slots {
		slots[i] = common.TreeSlotParams{ID: big.NewInt(0), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(0)}
	}
	return slots
}

// baseParams builds the audit statement over the ringaudit default scalars.
func baseParams(t *testing.T) *BaseParams {
	t.Helper()
	p := &BaseParams{
		CircuitType: string(common.CustomRingBaseCircuitType),
		AuditParams: AuditParams{
			PrivateTxHash: fi(0xabcdef), TxViewingSk: testScalar(0x11), EphSk: testScalar(0x22),
			AuditorPk: auditorKey(t, 0x33), Salt: make(Bytes, 16),
		},
		NOut:    1,
		Outputs: []AuditOpening{zeroAuditOpening(), zeroAuditOpening(), zeroAuditOpening(), zeroAuditOpening()},
	}
	keys := ringaudit.DefaultKeys(t)
	p.PublicInputHash = fb(spptest.MustHashChain(t, keys.ChainElements(t, p.PrivateTxHash.Int)))
	return p
}

// rulesFreeParams opens a one input one output transfer against a length zero
// rule table, both owners absent from an otherwise listed registry.
func rulesFreeParams(t *testing.T) (*PolicyParams, *spptest.MemberRegistry) {
	return rulesFreeParamsAtRoot(t, big.NewInt(0x0d))
}

func rulesFreeParamsAtRoot(t *testing.T, root *big.Int) (*PolicyParams, *spptest.MemberRegistry) {
	t.Helper()
	p := &PolicyParams{
		CircuitType: string(common.CustomRingPolicyCircuitType),
		AuditParams: AuditParams{
			TxViewingSk: testScalar(0x11), EphSk: testScalar(0x22), AuditorPk: auditorKey(t, 0x33), Salt: make(Bytes, 16),
		},
		NIn: 1, NOut: 1,
		AddressChain: fi(0x77), PrivateTxBlinding: fi(0x5b1d),
		Rules:        zeros(policy.NRules),
		InlineAssets: zeros(policy.NInlineAssets), InlineLimits: zeros(policy.NInlineAssets),
		TreeSlots:     zeroTreeSlots(),
		AddressTreeID: fi(0x0f), RingID: fi(0x5a), NamespaceOwnerHash: fi(0x99), ForeignRoot: fi(0),
		Subjects: make([]*MemberOpening, policy.NSubjects), ForeignSubjects: make([]*MemberOpening, policy.NSubjects),
	}
	p.TreeSlots[0] = common.TreeSlotParams{ID: p.AddressTreeID.Int, UtxoRoot: root, NullifierRoot: big.NewInt(0x0e)}
	for range policy.NSources {
		p.Sources = append(p.Sources, Source{Registry: fi(0)})
	}
	for range policy.NOutflowLimits {
		p.Limits = append(p.Limits, OutflowLimit{fi(0), fi(0), fi(0)})
	}
	for range policy.NInputs {
		p.Inputs = append(p.Inputs, zeroOpening())
	}
	for range policy.NOutputs {
		p.Outputs = append(p.Outputs, OutputOpening{Opening: zeroOpening(), CtHash: fi(0)})
	}
	p.Inputs[0] = Opening{
		Domain: fi(protocol.UtxoDomain), TreeID: fi(0), OwnerPkHash: fi(0xb2), NullifierPk: fi(0xb3),
		Asset: fi(0xa5), Amount: fi(1000), Blinding: fi(0x51), DataHash: fi(0), RingDataHash: fi(0), RingProgramID: fi(0),
	}
	p.Outputs[0].Opening = Opening{
		Domain: fi(protocol.UtxoDomain), TreeID: fi(0), OwnerPkHash: fi(0xa1), NullifierPk: fi(0xa2),
		Asset: fi(0xa5), Amount: fi(1000), Blinding: fi(0x52), DataHash: fi(0), RingDataHash: fi(0), RingProgramID: fi(0),
	}
	members := spptest.NewMemberRegistry(t, registry.Height)
	members.Update(t, big.NewInt(0x0a), big.NewInt(1), big.NewInt(0))
	members.Update(t, big.NewInt(0xc0), big.NewInt(2), big.NewInt(0))
	openSubjects(p, members)
	bindRulesFreeStatement(t, p)
	return p, members
}

// openSubjects fills the opening of every live UTXO slot from the registry.
func openSubjects(p *PolicyParams, members *spptest.MemberRegistry) {
	p.MemberRegistryRoot = fb(members.Root())
	for i, input := range p.Inputs {
		if i < int(p.NIn) && input.Domain.Int64() == protocol.UtxoDomain {
			p.Subjects[i] = memberOpening(members.Opening(input.OwnerPkHash.Int))
		}
	}
	for o, output := range p.Outputs {
		if o < int(p.NOut) && output.Domain.Int64() == protocol.UtxoDomain {
			p.Subjects[policy.NInputs+o] = memberOpening(members.Opening(output.OwnerPkHash.Int))
		}
	}
}

func memberOpening(w spptest.MemberOpeningWitness) *MemberOpening {
	opening := &MemberOpening{Present: w.Present, LowMember: fi(0), LowNext: fi(0), LowEscrow: fi(0)}
	opening.RecordOpening = RecordOpening{Next: fi(0), EscrowKey: fi(0), Index: w.Index}
	for _, node := range w.Path {
		opening.Path = append(opening.Path, fb(new(big.Int).Set(&node)))
	}
	if w.Present {
		opening.Next, opening.Lists, opening.EscrowKey = fb(w.Record.Next), w.Record.Lists.Uint64(), fb(w.Record.EscrowKey)
		return opening
	}
	opening.LowMember, opening.LowNext, opening.LowLists, opening.LowEscrow = fb(w.Record.Member), fb(w.Record.Next), w.Record.Lists.Uint64(), fb(w.Record.EscrowKey)
	return opening
}

// bindRulesFreeStatement binds the public chain of a policy without rules.
func bindRulesFreeStatement(t *testing.T, p *PolicyParams) {
	t.Helper()
	inputs, outputs := []*big.Int{}, []*big.Int{}
	for i := range int(p.NIn) {
		inputs = append(inputs, openingHash(t, p.Inputs[i]))
	}
	for i := range int(p.NOut) {
		outputs = append(outputs, openingHash(t, p.Outputs[i].Opening))
	}
	p.PrivateTxHash = fb(spptest.MustPoseidon(t, 5, []*big.Int{
		spptest.MustNonZeroHashChain(t, inputs), spptest.MustNonZeroHashChain(t, outputs),
		p.AddressChain.Int, p.PrivateTxBlinding.Int,
	}))
	// Mirrors ring_policy::packed_ascii of the policy table domain tag.
	tableDomain := new(big.Int).SetBytes([]byte("zolana:ring-policy:policy:v1"))
	preimage := []*big.Int{tableDomain, big.NewInt(policy.PolicyVersion)}
	for _, source := range p.Sources {
		preimage = append(preimage, big.NewInt(int64(source.ListId)), source.Registry.Int)
	}
	preimage = append(preimage, big.NewInt(0), big.NewInt(0), big.NewInt(int64(p.LimitCount)))
	for _, row := range p.Limits[:p.LimitCount] {
		preimage = append(preimage, row.Asset.Int, row.Cap.Int, row.CosignAbove.Int)
	}
	policyHash := spptest.MustHashChain(t, preimage)
	elements := ringaudit.DefaultKeys(t).ChainElementsFor(t, policyAuditStatement(t, p))
	slots := make([]protocol.TreeSlot, len(p.TreeSlots))
	for i, slot := range p.TreeSlots {
		slots[i] = protocol.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	keyEscrow := big.NewInt(0)
	if p.KeyEscrow {
		keyEscrow.SetInt64(1)
	}
	elements = append(elements, policyHash, spptest.MustTreeSlotsHashChain(t, slots), p.AddressTreeID.Int,
		p.RingID.Int, p.NamespaceOwnerHash.Int, big.NewInt(0),
		keyEscrow, p.MemberRegistryRoot.Int, p.ForeignRoot.Int)
	p.PublicInputHash = fb(spptest.MustHashChain(t, elements))
}

func policyAuditStatement(t testing.TB, p *PolicyParams) ringaudit.Statement {
	t.Helper()
	statement := ringaudit.DefaultKeys(t).Statement(p.PrivateTxHash.Int)
	statement.Count = int(p.NOut)
	for i, value := range p.Salt {
		statement.Audit.Salt[i] = int(value)
	}
	for i, output := range p.Outputs {
		statement.Outputs[i] = base.AuditOutputWires{
			Domain: output.Domain.Int, TreeID: output.TreeID.Int,
			OwnerHash: spptest.MustPoseidon(t, 3, []*big.Int{output.OwnerPkHash.Int, output.NullifierPk.Int}),
			Asset:     output.Asset.Int, Amount: output.Amount.Int, Blinding: output.Blinding.Int,
			DataHash: output.DataHash.Int, RingDataHash: output.RingDataHash.Int, RingProgramID: output.RingProgramID.Int,
		}
	}
	return statement
}

func openingHash(t *testing.T, slot Opening) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: slot.Domain.Int, Owner: spptest.MustOwnerHash(t, slot.OwnerPkHash.Int, slot.NullifierPk.Int),
		Asset: slot.Asset.Int, Amount: slot.Amount.Int, Blinding: slot.Blinding.Int,
		DataHash: slot.DataHash.Int, RingDataHash: slot.RingDataHash.Int, RingProgramID: slot.RingProgramID.Int,
	}, slot.TreeID.Int)
}

// escrowPolicyOutputs registers every live output owner's key and turns escrow on.
func escrowPolicyOutputs(t *testing.T, p *PolicyParams, members *spptest.MemberRegistry) {
	t.Helper()
	for o := range int(p.NOut) {
		output := &p.Outputs[o]
		if output.Domain.Int64() != protocol.UtxoDomain {
			continue
		}
		output.CtHash = fi(int64(0xc0 + o))
		members.RegisterKey(t, output.OwnerPkHash.Int, output.NullifierPk.Int, output.CtHash.Int)
	}
	p.KeyEscrow = true
	openSubjects(p, members)
	bindRulesFreeStatement(t, p)
}

// escrowDeposits registers every occupied slot's key and turns escrow on.
func escrowDeposits(t *testing.T, p *DepositParams) *spptest.MemberRegistry {
	t.Helper()
	members := spptest.NewMemberRegistry(t, registry.Height)
	for i := range int(p.Count) {
		p.CtHashes[i] = fi(int64(0xc0 + i))
		members.RegisterKey(t, p.OwnerPkHashes[i].Int, p.NullifierPks[i].Int, p.CtHashes[i].Int)
	}
	for i := range int(p.Count) {
		p.Members[i] = &memberOpening(members.Opening(p.OwnerPkHashes[i].Int)).RecordOpening
	}
	p.KeyEscrow, p.MemberRegistryRoot = true, fb(members.Root())
	return members
}

// depositParams fills count openings, the last blinding close to the field modulus.
func depositParams(t *testing.T, count uint32) *DepositParams {
	t.Helper()
	p := &DepositParams{
		CircuitType: string(common.CustomRingDepositCircuitType), ContextHash: fi(0xabcdef), Count: count,
		OwnerPkHashes: zeros(deposit.MaxDeposits), NullifierPks: zeros(deposit.MaxDeposits), Blindings: zeros(deposit.MaxDeposits),
		CtHashes: zeros(deposit.MaxDeposits), Members: make([]*RecordOpening, deposit.MaxDeposits),
		EphSk: testScalar(0x22), AuditorPk: auditorKey(t, 0x33), MemberRegistryRoot: fi(0),
	}
	for i := range int(count) {
		p.OwnerPkHashes[i] = fi(int64(11 + i))
		p.NullifierPks[i] = fb(spptest.MustNullifierPk(t, big.NewInt(int64(51+i))))
		p.Blindings[i] = fi(int64(91 + i))
	}
	p.Blindings[count-1] = fb(new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)))
	return p
}

// registerKeyParams seals a nullifier secret for member and writes the key into its record.
func registerKeyParams(t *testing.T, members *spptest.MemberRegistry, member *big.Int) *KeyRegisterParams {
	t.Helper()
	secret := ringaudit.Scalar(0x07)
	secret[0] = 0
	keys := ringaudit.DefaultKeys(t)
	sealed := keys.Seal(t, secret[:], policy.NfKeyEncInfo)
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:]))
	update := members.RegisterKey(t, member, nullifierPk, sealed.CiphertextHash)
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	p := &KeyRegisterParams{
		CircuitType:     string(common.CustomRingKeyRegisterCircuitType),
		RegistryOldRoot: fb(update.OldRoot), RegistryNewRoot: fb(update.NewRoot), Member: fb(member), Lists: update.Lists.Uint64(),
		RecordUpdate:    recordUpdate(update),
		NullifierSecret: secret[:], EphSk: eph[:], AuditorPk: auditor[:],
	}
	p.PublicInputHash = fb(spptest.MustHashChain(t, []*big.Int{
		update.OldRoot, update.NewRoot, member, nullifierPk,
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash, new(big.Int).SetUint64(update.Index),
	}))
	return p
}

func recordUpdate(w spptest.MemberUpdateWitness) RecordUpdate {
	u := RecordUpdate{Exists: w.Exists, Next: fb(w.Next), Index: w.Index, LowMember: fi(0), LowNext: fi(0), LowEscrow: fi(0), LowPath: zeros(registry.Height)}
	for _, node := range w.Path {
		u.Path = append(u.Path, fb(new(big.Int).Set(&node)))
	}
	if w.Exists {
		return u
	}
	u.LowMember, u.LowNext, u.LowLists, u.LowEscrow, u.LowIndex = fb(w.Low.Member), fb(w.Low.Next), w.Low.Lists.Uint64(), fb(w.Low.EscrowKey), w.LowIndex
	u.LowPath = nil
	for _, node := range w.LowPath {
		u.LowPath = append(u.LowPath, fb(new(big.Int).Set(&node)))
	}
	return u
}

// updateMembersParams applies a batch of inserts and rewrites and binds the statement.
func updateMembersParams(t *testing.T, members *spptest.MemberRegistry, items [][3]*big.Int) *UpdateMembersParams {
	t.Helper()
	p := &UpdateMembersParams{
		CircuitType: string(common.CustomRingUpdateMembersCircuitType), OldRoot: fb(members.Root()),
		ItemCount: uint8(len(items)), Items: make([]*MemberUpdate, registry.MaxBatch),
	}
	chain := []*big.Int{big.NewInt(int64(len(items)))}
	for i, item := range items {
		update := members.Update(t, item[0], item[1], item[2])
		p.Items[i] = &MemberUpdate{
			Member: fb(update.Member), OldLists: update.OldLists.Uint64(), OldEscrowKey: fb(update.OldEscrow),
			Lists: update.Lists.Uint64(), EscrowKey: fb(update.EscrowKey), RecordUpdate: recordUpdate(update),
		}
		chain = append(chain, update.Member, update.OldLists, update.OldEscrow, update.Lists, update.EscrowKey, new(big.Int).SetUint64(update.Index))
	}
	for i := len(items); i < registry.MaxBatch; i++ {
		chain = append(chain, spptest.RepeatBigInt(big.NewInt(0), 6)...)
	}
	p.NewRoot = fb(members.Root())
	p.PublicInputHash = fb(spptest.MustHashChain(t, []*big.Int{p.OldRoot.Int, p.NewRoot.Int, spptest.MustHashChain(t, chain)}))
	return p
}

func verifyProof(ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, ps.VerifyingKey, witness)
}
