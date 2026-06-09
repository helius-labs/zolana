package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

// proveTestOwner builds the Solana-signer owner material shared by the dummy
// padding tests.
func proveTestOwner(t *testing.T) (signerPubkey [32]byte, signerHash, owner, nullifierSecret *big.Int) {
	t.Helper()
	for i := range signerPubkey {
		signerPubkey[i] = byte(i + 1)
	}
	signerHash = protocol.Sha256BEField(signerPubkey[:])
	ownerKeyHash, err := protocol.SolanaPkHash(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierSecret = big.NewInt(12345)
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err = protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	return signerPubkey, signerHash, owner, nullifierSecret
}

func solOutput(owner *big.Int, amount, blinding int64) ProofUtxoRequest {
	return ProofUtxoRequest{
		Domain:        proofFieldInput(big.NewInt(protocol.UtxoDomain)),
		Owner:         proofFieldInput(owner),
		AssetID:       proofFieldInput(big.NewInt(protocol.SolAssetID)),
		AssetAmount:   proofFieldInput(big.NewInt(amount)),
		Blinding:      proofFieldInput(big.NewInt(blinding)),
		DataHash:      proofFieldInput(big.NewInt(0)),
		ZoneDataHash:  proofFieldInput(big.NewInt(0)),
		ZoneProgramID: proofFieldInput(big.NewInt(0)),
	}
}

func proveAndVerify(t *testing.T, shape protocol.Shape, tx ProofTransactionRequest, signerHash *big.Int) {
	t.Helper()
	ps, err := Setup(shape)
	if err != nil {
		t.Fatal(err)
	}
	assignment, _, _, _, _, err := buildProofAssignment(shape, tx, signerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	proof, err := Prove(ps, assignment)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := Verify(ps, assignment, proof); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestProveTransferWithDummyPadding proves a 1-in/1-out transfer inside a 2-2
// shape: the extra input and output slots are dummies. This exercises the dummy
// gating on both sides through real Groth16 proving and verification.
func TestProveTransferWithDummyPadding(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	signerPubkey, signerHash, owner, nullifierSecret := proveTestOwner(t)

	input := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         owner,
		AssetID:       big.NewInt(protocol.SolAssetID),
		AssetAmount:   big.NewInt(100),
		Blinding:      big.NewInt(1000),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
	inputHash, err := protocol.UtxoHash(input)
	if err != nil {
		t.Fatal(err)
	}

	tx := ProofTransactionRequest{
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		PublicAmountMode:         publicAmountTransfer,
		EncryptedUtxos:           "00",
		ProgramIDHashchain:       proofFieldInput(big.NewInt(0)),
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
		StateEntries: []ProofStateEntry{
			{Index: 0, Hash: proofFieldInput(inputHash)},
		},
		Inputs: []ProofInputRequest{
			{
				Utxo: ProofUtxoRequest{
					Domain:            proofFieldInput(input.Domain),
					OwnerSolanaPubkey: parse.BytesHex(signerPubkey[:]),
					AssetID:           proofFieldInput(input.AssetID),
					AssetAmount:       proofFieldInput(input.AssetAmount),
					Blinding:          proofFieldInput(input.Blinding),
					DataHash:          proofFieldInput(input.DataHash),
					ZoneDataHash:      proofFieldInput(input.ZoneDataHash),
					ZoneProgramID:     proofFieldInput(input.ZoneProgramID),
				},
				LeafIndex:       0,
				NullifierSecret: proofFieldInput(nullifierSecret),
			},
		},
		Outputs: []ProofUtxoRequest{
			solOutput(owner, 100, 2000),
		},
	}

	proveAndVerify(t, shape, tx, signerHash)
}

// TestProveShieldWithAllDummyInputs proves a deposit (shield) inside a 1-2 shape
// with zero real inputs: the lone input slot is a dummy and a public SOL deposit
// funds the two real outputs. This is the case the exact-shape circuit could not
// express; dummy support is what makes it provable.
func TestProveShieldWithAllDummyInputs(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	_, signerHash, owner, _ := proveTestOwner(t)

	deposit := uint64(100)
	tx := ProofTransactionRequest{
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		PublicAmountMode:         publicAmountShield,
		PublicSolAmount:          &deposit,
		EncryptedUtxos:           "00",
		ProgramIDHashchain:       proofFieldInput(big.NewInt(0)),
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
		Outputs: []ProofUtxoRequest{
			solOutput(owner, 60, 2000),
			solOutput(owner, 40, 2001),
		},
	}

	proveAndVerify(t, shape, tx, signerHash)
}
