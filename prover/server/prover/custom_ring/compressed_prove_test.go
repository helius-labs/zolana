package custom_ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/custom_rings/circuits/policy"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

func TestCompressedSuccessorProofVerifies(t *testing.T) {
	transferSystem := loadRingSystem(t, common.CustomRingCompressedPolicyKeyFile)
	var decodedTransfer CompressedPolicyParameters
	roundTripProofParameters(t, compressedProofParameters(t, nil), &decodedTransfer)
	transferProof, err := Prove(transferSystem, &decodedTransfer)
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
	transfer := compressedProofParameters(t, func(p *PolicyParameters) {
		unknownCounters(p)
		p.Record.Window--
	})
	ps := loadRingSystem(t, common.CustomRingCompressedPolicyKeyFile)
	var decoded CompressedPolicyParameters
	roundTripProofParameters(t, transfer, &decoded)
	proof, err := Prove(ps, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, ps, proof, assignment)

	decoded.Base.WindowIndex = decoded.Base.Record.Window
	bindRulesFreeStatement(t, &decoded.Base, compressedDisclosure(t, &decoded))
	staleWindow, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	rejectInstalledProof(t, ps, proof, staleWindow)
	if _, err := Prove(ps, &decoded); err == nil {
		t.Fatal("an expired successor was proven under the predecessor window")
	}

	live := compressedProofParameters(t, unknownCounters)
	if _, err := Prove(ps, live); err == nil {
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
	proof, err := Prove(ps, &decoded)
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

func compressedProofParameters(t *testing.T, configure func(*PolicyParameters)) *CompressedPolicyParameters {
	t.Helper()
	p := rulesFreeParams(t)
	zero := big.NewInt(0)
	member := p.Inputs[0].OwnerPkHash
	ownerPk, nullifierPk := big.NewInt(0xf1), spptest.MustNullifierPk(t, zero)
	p.NamespaceOwnerHash = spptest.MustOwnerHash(t, ownerPk, nullifierPk)
	p.NIn, p.NOut, p.WindowSlots, p.WindowIndex, p.VelocityCount = 2, 2, 100, 7, 1
	p.AddressChain = spptest.MustHashChain4(t, spptest.RepeatBigInt(zero, int(p.NIn)))
	p.Velocity[0] = VelocityRow{Asset: p.Inputs[0].Asset, Cap: big.NewInt(5000), CosignAbove: big.NewInt(2000)}
	p.Record.Window = p.WindowIndex
	p.Record.NextSalt = big.NewInt(99)
	p.Record.Commitment = proofCounters(t, p.Record.Salt, zero, zero)
	if configure != nil {
		configure(p)
	}
	nextCommitment := proofCounters(t, p.Record.NextSalt, p.Velocity[0].Asset, p.Inputs[0].Amount)
	seed := spptest.MustPoseidon(t, 3, []*big.Int{policy.SpendAddressDomain, member})
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
				policy.SpendRecordDomain, address, member,
				new(big.Int).SetUint64(version), new(big.Int).SetUint64(window), commitment,
			}),
		}
	}
	p.Inputs[1], p.Outputs[1] = opening(p.Record.Version, p.Record.Commitment, 101), opening(p.Record.Version+1, nextCommitment, 102)
	transfer := &CompressedPolicyParameters{Base: *p}
	bindRulesFreeStatement(t, &transfer.Base, compressedDisclosure(t, transfer))
	return transfer
}

func proofCounters(t *testing.T, salt, asset, spent *big.Int) *big.Int {
	t.Helper()
	elements := []*big.Int{salt, asset, spent}
	for i := 1; i < policy.NVelocityAssets; i++ {
		elements = append(elements, big.NewInt(0), big.NewInt(0))
	}
	return spptest.MustHashChain(t, elements)
}

func compressedDisclosure(t *testing.T, p *CompressedPolicyParameters) *big.Int {
	return (spptest.CounterDisclosure{Secret: p.Base.TxViewingSk, TransactionSalt: p.TransactionSalt,
		CounterSalt: p.Base.Record.NextSalt, Assets: []*big.Int{p.Base.Velocity[0].Asset},
		Spent: []uint64{p.Base.Inputs[0].Amount.Uint64()}}).Hash(t)
}
