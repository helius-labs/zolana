package merge

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

const (
	proveFixtureInputTreeID  = 7
	proveFixtureOutputTreeID = 11
	proveFixtureRingProgram  = 71
)

func TestMergeProofCarriesCommitmentOnlyOnDefaultRail(t *testing.T) {
	cases := []struct {
		circuitType    common.CircuitType
		wantCommitment bool
		setup          func(uint32) (*common.TransferProofSystem, error)
	}{
		{common.MergeCircuitType, true, SetupMerge},
		{common.MergeRingCircuitType, false, SetupMergeRing},
	}
	for _, tc := range cases {
		t.Run(string(tc.circuitType), func(t *testing.T) {
			params := provableParams(t, tc.circuitType)
			request, err := json.Marshal(params)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			var decoded MergeParameters
			if err := json.Unmarshal(request, &decoded); err != nil {
				t.Fatalf("unmarshal request: %v", err)
			}

			start := time.Now()
			system, err := tc.setup(defaultTestNInputs)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			setupTime := time.Since(start)
			if system.RequiresP256 != tc.wantCommitment {
				t.Fatalf("RequiresP256: got %v want %v", system.RequiresP256, tc.wantCommitment)
			}

			start = time.Now()
			proof, err := MergeProof{System: system, Parameters: &decoded}.Prove()
			if err != nil {
				t.Fatalf("prove: %v", err)
			}
			t.Logf("%s: %d constraints, setup %s, prove %s",
				tc.circuitType, system.ConstraintSystem.GetNbConstraints(), setupTime, time.Since(start))

			encoded, err := json.Marshal(proof)
			if err != nil {
				t.Fatalf("marshal proof: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("unmarshal proof fields: %v", err)
			}
			for _, key := range []string{"proofCommitment", "proofCommitmentPok"} {
				if _, ok := fields[key]; ok != tc.wantCommitment {
					t.Fatalf("%s present = %v, want %v in %s", key, ok, tc.wantCommitment, encoded)
				}
			}

			var reread common.Proof
			if err := json.Unmarshal(encoded, &reread); err != nil {
				t.Fatalf("unmarshal proof: %v", err)
			}
			assignment, err := decoded.CreateWitness()
			if err != nil {
				t.Fatalf("create witness: %v", err)
			}
			public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatalf("public witness: %v", err)
			}
			if err := groth16.Verify(reread.Proof, system.VerifyingKey, public); err != nil {
				t.Fatalf("verify proof decoded from JSON: %v", err)
			}
		})
	}
}

func provableParams(t testing.TB, circuitType common.CircuitType) *MergeParameters {
	t.Helper()
	ring := circuitType == common.MergeRingCircuitType

	var solanaPubkey [32]byte
	solanaPubkey[31] = 0x2a
	ownerKeyHash, err := protocol.SolanaPkField(solanaPubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierSecret := big.NewInt(19)
	userNullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	ownerHash := spptest.MustOwnerHash(t, ownerKeyHash, userNullifierPk)

	var mint [32]byte
	for i := range mint {
		mint[i] = byte(i + 1)
	}
	asset, err := protocol.HashBytes(mint[:])
	if err != nil {
		t.Fatal(err)
	}

	ringProgramID := big.NewInt(0)
	inputRingData := []*big.Int{big.NewInt(0), big.NewInt(0)}
	outputRingData := big.NewInt(0)
	if ring {
		ringProgramID = big.NewInt(proveFixtureRingProgram)
		inputRingData = []*big.Int{big.NewInt(31), big.NewInt(32)}
		outputRingData = big.NewInt(33)
	}

	amounts := []*big.Int{big.NewInt(5), big.NewInt(7)}
	blindings := []*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}
	inputHashes := make([]*big.Int, len(amounts))
	stateEntries := map[uint64]*big.Int{}
	for i := range amounts {
		inputHashes[i] = spptest.MustUtxoHash(t, protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         ownerHash,
			Asset:         asset,
			Amount:        amounts[i],
			Blinding:      blindings[i],
			DataHash:      big.NewInt(0),
			RingDataHash:  inputRingData[i],
			RingProgramID: ringProgramID,
		}, big.NewInt(proveFixtureInputTreeID))
		stateEntries[uint64(i)] = inputHashes[i]
	}
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, stateEntries)

	nullifierTree := spptest.MustNewNullifierTree(t)
	nullifiers := make([]*big.Int, defaultTestNInputs)
	exclusions := make([]protocol.NonInclusionWitness, defaultTestNInputs)
	for i := range inputHashes {
		nullifiers[i] = spptest.MustNullifier(t, inputHashes[i], blindings[i], nullifierSecret)
	}
	for i := len(inputHashes); i < defaultTestNInputs; i++ {
		nullifiers[i] = mustPoseidon(t,
			big.NewInt(mergeshared.MergeDummyNullifierDomain), nullifierSecret, nullifiers[0], big.NewInt(int64(i)))
	}
	for i := range nullifiers {
		exclusions[i] = spptest.MustNonInclusion(t, nullifierTree, nullifiers[i])
	}

	treeSlots, err := protocol.PadTreeSlots(protocol.TreeSlot{
		ID:            big.NewInt(proveFixtureInputTreeID),
		UtxoRoot:      stateRoot,
		NullifierRoot: nullifierTree.Root(),
	})
	if err != nil {
		t.Fatal(err)
	}

	outAmount := new(big.Int).Add(amounts[0], amounts[1])
	params := &MergeParameters{
		CircuitType:         circuitType,
		Mint:                mint,
		RingProgramID:       ringProgramID,
		OwnerPkHash:         ownerKeyHash,
		UserNullifierPk:     userNullifierPk,
		UserNullifierSecret: nullifierSecret,
		OutputRingDataHash:  outputRingData,
		OutputTreeID:        big.NewInt(proveFixtureOutputTreeID),
		ExternalDataHash:    big.NewInt(0xABCDEF),
		AllowDummyInputs:    big.NewInt(1),
	}

	var envelope []*big.Int
	outBlinding := mustPoseidon(t, big.NewInt(mergeshared.MergeOutputBlindingDomainV1), nullifierSecret, nullifiers[0])
	if !ring {
		keys := hosttest.DefaultKeys()
		plaintext := make([]byte, mergeshared.MergeAmountBytes, mergeshared.MergeCiphertextBytes)
		outAmount.FillBytes(plaintext)
		plaintext = append(plaintext, mint[:]...)
		ciphertext, sharedSecret := keys.Seal(mergeshared.MergeSecretTag, mergeshared.MergeKdfInfo, plaintext)
		outBlinding = mustPoseidon(t, big.NewInt(mergeshared.MergeDerivedBlindingDomain), sharedSecret)
		params.ViewingPk = keys.RecipientUncompressed()
		params.EphemeralSk = keys.EphemeralScalar()
		envelope = envelopePublicElements(keys, ciphertext)
	}

	outHash := spptest.MustUtxoHash(t, protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         ownerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      outBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  outputRingData,
		RingProgramID: ringProgramID,
	}, params.OutputTreeID)

	privateInputs := make([]*big.Int, defaultTestNInputs)
	for i := range privateInputs {
		privateInputs[i] = big.NewInt(0)
		if i < len(inputHashes) {
			privateInputs[i] = inputHashes[i]
		}
	}
	privateTxBlinding, err := protocol.PrivateTxBlinding(nullifiers[0], nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	params.PrivateTxHash = spptest.MustPrivateTxHash(t, privateInputs, []*big.Int{outHash}, zeros(defaultTestNInputs), privateTxBlinding)
	params.Output = OutputParams{RingDataHash: outputRingData, Hash: outHash}

	preimage := []*big.Int{
		spptest.MustRightHashChain4(t, nullifiers),
		outHash,
		spptest.MustTreeSlotsHashChain(t, treeSlots),
		params.OutputTreeID,
		params.PrivateTxHash,
		params.ExternalDataHash,
		params.AllowDummyInputs,
	}
	if ring {
		preimage = append(preimage, outputRingData, ringProgramID)
	} else {
		preimage = append(preimage, ownerKeyHash, userNullifierPk)
		preimage = append(preimage, envelope...)
	}
	params.PublicInputHash = spptest.MustHashChain4(t, preimage)

	params.TreeSlots = make([]common.TreeSlotParams, len(treeSlots))
	for k, slot := range treeSlots {
		params.TreeSlots[k] = common.TreeSlotParams{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}

	params.Inputs = make([]InputParams, defaultTestNInputs)
	for i := range params.Inputs {
		exclusion := exclusions[i]
		input := InputParams{
			Domain:                   big.NewInt(protocol.DummyDomain),
			Amount:                   big.NewInt(0),
			Blinding:                 big.NewInt(0),
			RingDataHash:             big.NewInt(0),
			StatePathElements:        zeros(transaction.StateTreeHeight),
			StatePathIndex:           big.NewInt(0),
			NullifierLowValue:        exclusion.LowValue,
			NullifierNextValue:       exclusion.NextValue,
			NullifierLowPathElements: exclusion.PathElements,
			NullifierLowPathIndex:    new(big.Int).SetUint64(exclusion.LowIndex),
			TreeSlot:                 big.NewInt(0),
			Nullifier:                nullifiers[i],
		}
		if i < len(inputHashes) {
			state := stateProofs[uint64(i)]
			input.Domain = big.NewInt(protocol.UtxoDomain)
			input.Amount = amounts[i]
			input.Blinding = blindings[i]
			input.RingDataHash = inputRingData[i]
			input.StatePathElements = state.PathElements
			input.StatePathIndex = new(big.Int).SetUint64(state.PathIndex)
		}
		params.Inputs[i] = input
	}
	return params
}

func envelopePublicElements(keys hosttest.Keys, ciphertext []byte) []*big.Int {
	head := mergeshared.MergeHeadChunkCiphertextBytes
	recipientLo, recipientHi := keys.RecipientPacked()
	ephemeralLo, ephemeralHi := keys.EphemeralPacked()
	packed := new(big.Int).Lsh(recipientHi, 8*(2+uint(head)))
	packed.Add(packed, new(big.Int).Lsh(ephemeralHi, 8*uint(head)))
	packed.Add(packed, new(big.Int).SetBytes(ciphertext[:head]))
	return []*big.Int{
		recipientLo,
		ephemeralLo,
		packed,
		new(big.Int).SetBytes(ciphertext[head:mergeshared.MergeCiphertextBytes]),
	}
}

func mustPoseidon(t testing.TB, inputs ...*big.Int) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
