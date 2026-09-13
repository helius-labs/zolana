package custom_ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/policy"
	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

func TestCompressedRegistrationAndSuccessorProofsVerify(t *testing.T) {
	register, transfer := compressedProofParameters(t, nil)
	registerSystem := loadRingSystem(t, common.CompressedRegisterKeyFile)
	var decodedRegister CompressedRegisterParameters
	roundTripProofParameters(t, register, &decodedRegister)
	registrationProof, err := ProveCompressedRegister(registerSystem, &decodedRegister)
	if err != nil {
		t.Fatal(err)
	}
	registrationAssignment, err := decodedRegister.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, registerSystem, registrationProof, registrationAssignment)
	registrationAssignment.PublicInputHash = big.NewInt(1)
	rejectInstalledProof(t, registerSystem, registrationProof, registrationAssignment)

	transferSystem := loadRingSystem(t, common.CompressedPolicyKeyFile)
	var decodedTransfer CompressedPolicyParameters
	roundTripProofParameters(t, transfer, &decodedTransfer)
	transferProof, err := ProveCompressedPolicy(transferSystem, &decodedTransfer)
	if err != nil {
		t.Fatal(err)
	}
	transferAssignment, err := decodedTransfer.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, transferSystem, transferProof, transferAssignment)
	transferAssignment.Policy.PublicInputHash = big.NewInt(1)
	rejectInstalledProof(t, transferSystem, transferProof, transferAssignment)
}

func TestCompressedProofResetsExpiredCountersWithoutTheirOpening(t *testing.T) {
	unknownCounters := func(p *PolicyParameters) {
		p.Record.Version = 3
		p.Record.Commitment = proofCounters(t, big.NewInt(71), p.Velocity[0].Asset, p.Velocity[0].Cap)
	}
	_, transfer := compressedProofParameters(t, func(p *PolicyParameters) {
		unknownCounters(p)
		p.Record.Window--
	})
	ps := loadRingSystem(t, common.CompressedPolicyKeyFile)
	var decoded CompressedPolicyParameters
	roundTripProofParameters(t, transfer, &decoded)
	proof, err := ProveCompressedPolicy(ps, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, ps, proof, assignment)

	decoded.Base.WindowIndex = decoded.Base.Record.Window
	bindRulesFreeStatement(t, &decoded.Base, decoded.HeadOldRoot, decoded.HeadNewRoot)
	staleWindow, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	rejectInstalledProof(t, ps, proof, staleWindow)
	if _, err := ProveCompressedPolicy(ps, &decoded); err == nil {
		t.Fatal("an expired successor was proven under the predecessor window")
	}

	_, live := compressedProofParameters(t, unknownCounters)
	if _, err := ProveCompressedPolicy(ps, live); err == nil {
		t.Fatal("a live record was proven without its counter opening")
	}
}

func TestDelegateProofVerifiesAboveCommittedWindowCap(t *testing.T) {
	p := rulesFreeParams(t)
	p.WindowSlots, p.VelocityCount = 100, 1
	p.Velocity[0] = VelocityRow{Asset: p.Inputs[0].Asset, Cap: big.NewInt(1), CosignAbove: big.NewInt(1)}
	bindRulesFreeStatement(t, p)
	params := DelegatePolicyParameters{Policy: *p}
	var decoded DelegatePolicyParameters
	roundTripProofParameters(t, &params, &decoded)
	ps := loadRingSystem(t, common.CustomRingDelegatePolicyKeyFile)
	proof, err := ProveDelegatePolicy(ps, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	base, err := decoded.Policy.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	assignment := &policy.CustomRingDelegatePolicyCircuit{Policy: *base}
	verifyInstalledProof(t, ps, proof, assignment)
	rejectInstalledProof(t, loadRingSystem(t, common.CustomRingPolicyKeyFile), proof, assignment)
}

func roundTripProofParameters(t *testing.T, source, target any) {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func verifyInstalledProof(t *testing.T, ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) {
	t.Helper()
	if err := verifyProofAssignment(ps, proof, assignment); err != nil {
		t.Fatal(err)
	}
}

func rejectInstalledProof(t *testing.T, ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) {
	t.Helper()
	if err := verifyProofAssignment(ps, proof, assignment); err == nil {
		t.Fatal("proof admitted under a different statement or rail")
	}
}

func verifyProofAssignment(ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, ps.VerifyingKey, witness)
}

func compressedProofParameters(t *testing.T, configure func(*PolicyParameters)) (*CompressedRegisterParameters, *CompressedPolicyParameters) {
	t.Helper()
	p := rulesFreeParams(t)
	zero := big.NewInt(0)
	member := p.Inputs[0].OwnerPkHash
	ownerPk, nullifierPk := big.NewInt(0xf1), spptest.MustNullifierPk(t, zero)
	p.NamespaceOwnerHash = spptest.MustOwnerHash(t, ownerPk, nullifierPk)
	p.NIn, p.NOut, p.WindowSlots, p.WindowIndex, p.VelocityCount = 2, 2, 100, 7, 1
	p.Velocity[0] = VelocityRow{Asset: p.Inputs[0].Asset, Cap: big.NewInt(5000), CosignAbove: big.NewInt(2000)}
	p.Record.Window = p.WindowIndex
	p.Record.NextSalt = big.NewInt(99)
	p.Record.Commitment = proofCounters(t, p.Record.Salt, zero, zero)
	if configure != nil {
		configure(p)
	}
	nextCommitment := proofCounters(t, p.Record.NextSalt, p.Velocity[0].Asset, p.Inputs[0].Amount)
	seed := spptest.MustPoseidon(t, 3, []*big.Int{new(big.Int).SetBytes([]byte("zolana:ring-policy:spend:v1")), member})
	addressLeaf := spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.AddressDomain), Owner: p.NamespaceOwnerHash,
		Asset: zero, Amount: zero, Blinding: seed, DataHash: zero, RingDataHash: zero, RingProgramID: zero,
	}, p.EntriesTreeID)
	address := spptest.MustNullifier(t, addressLeaf, seed, zero)
	opening := func(version uint64, commitment *big.Int, blinding int64) Opening {
		window := p.WindowIndex
		if version == p.Record.Version {
			window = p.Record.Window
		}
		return Opening{
			Domain: big.NewInt(protocol.UtxoDomain), TreeID: p.EntriesTreeID,
			OwnerPkHash: ownerPk, NullifierPk: nullifierPk, Asset: protocol.SolAsset(), Amount: zero,
			Blinding: big.NewInt(blinding), RingProgramID: zero, RingDataHash: zero,
			DataHash: spptest.MustPoseidon(t, 7, []*big.Int{
				new(big.Int).SetBytes([]byte("zolana:ring-spend:record:v1")), address, member,
				new(big.Int).SetUint64(version), new(big.Int).SetUint64(window), commitment,
			}),
		}
	}
	p.Inputs[1], p.Outputs[1] = opening(p.Record.Version, p.Record.Commitment, 101), opening(p.Record.Version+1, nextCommitment, 102)
	genesis := spptest.MustNullifier(t, openingHash(t, p.Inputs[1]), p.Inputs[1].Blinding, zero)
	successor := spptest.MustNullifier(t, openingHash(t, p.Outputs[1]), p.Outputs[1].Blinding, zero)
	maximum := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	leaf := func(owner, next, nullifier *big.Int) big.Int {
		return *spptest.MustPoseidon(t, 4, []*big.Int{owner, next, nullifier})
	}
	tree := merkletree.NewTree(policy.HeadMapHeight)
	tree.Update(0, leaf(zero, maximum, zero))
	emptyRoot, lowProof := tree.Root.Value(), tree.GenerateProof(0)
	tree.Update(0, leaf(zero, member, zero))
	emptyProof := tree.GenerateProof(1)
	tree.Update(1, leaf(member, maximum, genesis))
	registeredRoot, transferProof := tree.Root.Value(), tree.GenerateProof(1)
	tree.Update(1, leaf(member, maximum, successor))
	transferredRoot := tree.Root.Value()
	register := &CompressedRegisterParameters{
		HeadOldRoot: &emptyRoot, HeadNewRoot: &registeredRoot, Member: member, Genesis: genesis,
		NewIndex: big.NewInt(1), LowMember: zero, LowNext: maximum, LowNullifier: zero, LowIndex: zero,
	}
	register.PublicInputHash = spptest.MustHashChain(t, []*big.Int{
		register.HeadOldRoot, register.HeadNewRoot, member, genesis, register.NewIndex,
	})
	transfer := &CompressedPolicyParameters{
		Base: *p, HeadOldRoot: &registeredRoot, HeadNewRoot: &transferredRoot, HeadNext: maximum, HeadIndex: big.NewInt(1),
	}
	for i := range register.LowProof {
		register.LowProof[i], register.NewProof[i], transfer.HeadProof[i] = &lowProof[i], &emptyProof[i], &transferProof[i]
	}
	bindRulesFreeStatement(t, &transfer.Base, transfer.HeadOldRoot, transfer.HeadNewRoot)
	return register, transfer
}

func proofCounters(t *testing.T, salt, asset, spent *big.Int) *big.Int {
	t.Helper()
	elements := []*big.Int{salt, asset, spent}
	for i := 1; i < policy.NVelocityAssets; i++ {
		elements = append(elements, big.NewInt(0), big.NewInt(0))
	}
	return spptest.MustHashChain(t, elements)
}

func bindRulesFreeStatement(t *testing.T, p *PolicyParameters, tail ...*big.Int) {
	t.Helper()
	inputs, outputs := []*big.Int{}, []*big.Int{}
	for i := 0; i < int(p.NIn); i++ {
		inputs = append(inputs, openingHash(t, p.Inputs[i]))
	}
	for i := 0; i < int(p.NOut); i++ {
		outputs = append(outputs, openingHash(t, p.Outputs[i]))
	}
	p.PrivateTxHash = spptest.MustPoseidon(t, 6, []*big.Int{
		spptest.MustHashChain4(t, inputs), spptest.MustHashChain4(t, outputs),
		p.AddressChain, p.ExternalDataHash, p.PrivateTxBlinding,
	})
	preimage := []*big.Int{new(big.Int).SetBytes([]byte("zolana:ring-policy:policy:v1")), big.NewInt(policy.PolicyVersion)}
	for range p.Sources {
		preimage = append(preimage, big.NewInt(0), big.NewInt(0))
	}
	preimage = append(preimage, big.NewInt(0), big.NewInt(0), big.NewInt(int64(p.VelocityCount)), new(big.Int).SetUint64(p.WindowSlots))
	for i := 0; i < int(p.VelocityCount); i++ {
		row := p.Velocity[i]
		preimage = append(preimage, row.Asset, row.Cap, row.CosignAbove)
	}
	policyHash := spptest.MustHashChain(t, preimage)
	elements := []*big.Int{p.PrivateTxHash}
	for _, value := range auditChainElements {
		n, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			t.Fatal("invalid audit element")
		}
		elements = append(elements, n)
	}
	elements = append(elements, policyHash, p.StateRoot, p.NullifierRoot, p.EntriesTreeID,
		p.RingID, p.NamespaceOwnerHash, new(big.Int).SetUint64(p.WindowIndex), big.NewInt(0))
	p.PublicInputHash = spptest.MustHashChain(t, append(elements, tail...))
}
