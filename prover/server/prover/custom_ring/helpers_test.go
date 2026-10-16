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

func zeroListFact() ListFact {
	return ListFact{
		Member: fi(0), ContentHash: fi(0), Blinding: fi(0), NullifierLowValue: fi(0), NullifierNextValue: fi(0),
		NullifierLowPathElements: zeros(shared.NullifierTreeHeight), StatePathElements: zeros(shared.StateTreeHeight),
	}
}

func zeroRecord() SpendRecord {
	return SpendRecord{
		Commitment: fi(0), Salt: fi(0), NextSalt: fi(0),
		Assets: zeros(policy.NVelocityAssets), Spent: zeros(policy.NVelocityAssets),
	}
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
// rule table with every list fact slot disabled.
func rulesFreeParams(t *testing.T) *PolicyParams {
	return rulesFreeParamsAtRoot(t, big.NewInt(0x0d))
}

func rulesFreeParamsAtRoot(t *testing.T, root *big.Int) *PolicyParams {
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
		AddressTreeID: fi(0x0f), RingID: fi(0x5a), NamespaceOwnerHash: fi(0x99), KeyRegistryRoot: fi(0),
		Record: zeroRecord(),
	}
	p.TreeSlots[0] = common.TreeSlotParams{ID: p.AddressTreeID.Int, UtxoRoot: root, NullifierRoot: big.NewInt(0x0e)}
	for range policy.NSources {
		p.Sources = append(p.Sources, Source{OwnerHash: fi(0)})
	}
	for range policy.NVelocityAssets {
		p.Velocity = append(p.Velocity, VelocityRow{fi(0), fi(0), fi(0)})
	}
	for range policy.NInputs {
		p.Inputs = append(p.Inputs, zeroOpening())
	}
	for range policy.NOutputs {
		p.Outputs = append(p.Outputs, OutputOpening{Opening: zeroOpening()})
	}
	for range policy.NListFacts {
		p.ListFacts = append(p.ListFacts, zeroListFact())
	}
	p.Inputs[0] = Opening{
		Domain: fi(protocol.UtxoDomain), TreeID: fi(0), OwnerPkHash: fi(0xb2), NullifierPk: fi(0xb3),
		Asset: fi(0xa5), Amount: fi(1000), Blinding: fi(0x51), DataHash: fi(0), RingDataHash: fi(0), RingProgramID: fi(0),
	}
	p.Outputs[0].Opening = Opening{
		Domain: fi(protocol.UtxoDomain), TreeID: fi(0), OwnerPkHash: fi(0xa1), NullifierPk: fi(0xa2),
		Asset: fi(0xa5), Amount: fi(1000), Blinding: fi(0x52), DataHash: fi(0), RingDataHash: fi(0), RingProgramID: fi(0),
	}
	bindRulesFreeStatement(t, p)
	return p
}

// The tail extends the chain past the program context.
func bindRulesFreeStatement(t *testing.T, p *PolicyParams, tail ...*big.Int) {
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
	for range p.Sources {
		preimage = append(preimage, big.NewInt(0), big.NewInt(0))
	}
	preimage = append(preimage, big.NewInt(0), big.NewInt(0), big.NewInt(int64(p.VelocityCount)), new(big.Int).SetUint64(p.WindowSlots))
	for _, row := range p.Velocity[:p.VelocityCount] {
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
		p.RingID.Int, p.NamespaceOwnerHash.Int, new(big.Int).SetUint64(p.WindowIndex), big.NewInt(0),
		keyEscrow, p.KeyRegistryRoot.Int, big.NewInt(0))
	elements = append(elements, spptest.RepeatBigInt(big.NewInt(0), policy.NListFacts)...)
	p.PublicInputHash = fb(spptest.MustHashChain(t, append(elements, tail...)))
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

func registryKey(keys *spptest.KeyRegistry, key spptest.RegisteredKey) *RegistryKey {
	opening := &RegistryKey{Next: fb(key.Next), CtHash: fb(key.CtHash), Index: key.Index}
	for _, node := range keys.Path(key.Index) {
		opening.Path = append(opening.Path, fb(new(big.Int).Set(&node)))
	}
	return opening
}

// escrowDeposits registers every occupied slot's key and turns escrow on.
func escrowDeposits(t *testing.T, p *DepositParams) {
	t.Helper()
	keys := spptest.NewKeyRegistry(t, registry.Height)
	registered := make([]spptest.RegisteredKey, p.Count)
	for i := range registered {
		registered[i] = keys.Register(t, p.OwnerPkHashes[i].Int, p.NullifierPks[i].Int, big.NewInt(int64(0xc0+i)))
	}
	for i, key := range registered {
		p.Keys[i] = registryKey(keys, key)
	}
	p.KeyEscrow, p.KeyRegistryRoot = true, fb(keys.Root())
}

// depositParams fills count openings, the last blinding close to the field modulus.
func depositParams(t *testing.T, count uint32) *DepositParams {
	t.Helper()
	p := &DepositParams{
		CircuitType: string(common.CustomRingDepositCircuitType), ContextHash: fi(0xabcdef), Count: count,
		OwnerPkHashes: zeros(deposit.MaxDeposits), NullifierPks: zeros(deposit.MaxDeposits), Blindings: zeros(deposit.MaxDeposits),
		Keys: make([]*RegistryKey, deposit.MaxDeposits), EphSk: testScalar(0x22), AuditorPk: auditorKey(t, 0x33),
		KeyRegistryRoot: fi(0),
	}
	for i := range int(count) {
		p.OwnerPkHashes[i] = fi(int64(11 + i))
		p.NullifierPks[i] = fb(spptest.MustNullifierPk(t, big.NewInt(int64(51+i))))
		p.Blindings[i] = fi(int64(91 + i))
	}
	p.Blindings[count-1] = fb(new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)))
	return p
}

func verifyProof(ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, ps.VerifyingKey, witness)
}
