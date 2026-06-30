package transaction

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

// proveTestOwner builds the Solana-signer owner material shared by the dummy
// padding tests.
func proveTestOwner(t *testing.T) (payerPubkey [32]byte, payerHash, owner, nullifierSecret *big.Int) {
	t.Helper()
	for i := range payerPubkey {
		payerPubkey[i] = byte(i + 1)
	}
	payerHash = protocol.Sha256BEField(payerPubkey[:])
	ownerKeyHash, err := protocol.SolanaPkField(payerPubkey)
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
	return payerPubkey, payerHash, owner, nullifierSecret
}

func solOutput(owner *big.Int, amount, blinding int64) ProofUtxoRequest {
	return ProofUtxoRequest{
		Domain:        proofFieldInput(big.NewInt(protocol.UtxoDomain)),
		Owner:         proofFieldInput(owner),
		Asset:         proofFieldInput(protocol.SolAsset()),
		Amount:        proofFieldInput(big.NewInt(amount)),
		Blinding:      proofFieldInput(big.NewInt(blinding)),
		DataHash:      proofFieldInput(big.NewInt(0)),
		ZoneDataHash:  proofFieldInput(big.NewInt(0)),
		ZoneProgramID: proofFieldInput(big.NewInt(0)),
	}
}

func proveAndVerify(t *testing.T, shape protocol.Shape, tx ProofTransactionRequest, payerHash *big.Int) {
	t.Helper()
	ps, err := Setup(shape, TransactionRequiresP256(tx))
	if err != nil {
		t.Fatal(err)
	}
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	assignment := built.circuit
	proof, err := Prove(ps, assignment)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := Verify(ps, assignment, proof); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestProveTransferWithDummyPadding proves a 2-in/1-out transfer inside the
// canonical 2-2 shape: the second output slot is a dummy. This exercises the
// dummy output gating through real Groth16 proving and verification. (Dummy
// input slots are exercised by TestProveShieldWithAllDummyInputs. A non-minimal
// shape for these counts would be rejected, since SPP derives the vkey from the
// real counts via CanonicalShape.)
func TestProveTransferWithDummyPadding(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	payerPubkey, payerHash, owner, nullifierSecret := proveTestOwner(t)

	// Two inputs owned by the same Solana payer; distinct blindings give
	// distinct UTXO hashes and nullifiers. They fund a single real output, so
	// the second output slot in the 2-2 shape is a dummy.
	inputUtxos := []protocol.Utxo{
		{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: owner, Asset: protocol.SolAsset(),
			Amount: big.NewInt(60), Blinding: big.NewInt(1000),
			DataHash: big.NewInt(0), ZoneDataHash: big.NewInt(0), ZoneProgramID: big.NewInt(0),
		},
		{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: owner, Asset: protocol.SolAsset(),
			Amount: big.NewInt(40), Blinding: big.NewInt(1001),
			DataHash: big.NewInt(0), ZoneDataHash: big.NewInt(0), ZoneProgramID: big.NewInt(0),
		},
	}

	stateEntries := make([]ProofStateEntry, len(inputUtxos))
	inputs := make([]ProofInputRequest, len(inputUtxos))
	for i, input := range inputUtxos {
		inputHash, err := protocol.UtxoHash(input)
		if err != nil {
			t.Fatal(err)
		}
		stateEntries[i] = ProofStateEntry{Index: uint64(i), Hash: proofFieldInput(inputHash)}
		inputs[i] = ProofInputRequest{
			Utxo: ProofUtxoRequest{
				Domain:            proofFieldInput(input.Domain),
				OwnerSolanaPubkey: parse.BytesHex(payerPubkey[:]),
				Asset:             proofFieldInput(input.Asset),
				Amount:            proofFieldInput(input.Amount),
				Blinding:          proofFieldInput(input.Blinding),
				DataHash:          proofFieldInput(input.DataHash),
				ZoneDataHash:      proofFieldInput(input.ZoneDataHash),
				ZoneProgramID:     proofFieldInput(input.ZoneProgramID),
			},
			LeafIndex:       uint64(i),
			NullifierSecret: proofFieldInput(nullifierSecret),
		}
	}

	tx := ProofTransactionRequest{
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		PublicAmountMode:         publicAmountTransfer,
		EncryptedUtxos:           "00",
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
		StateEntries:             stateEntries,
		Inputs:                   inputs,
		Outputs: []ProofUtxoRequest{
			solOutput(owner, 100, 2000),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}

// TestProveShieldWithAllDummyInputs proves a deposit (shield) inside a 1-2 shape
// with zero real inputs: the lone input slot is a dummy and a public SOL deposit
// funds the two real outputs. This is the case the exact-shape circuit could not
// express; dummy support is what makes it provable.
func TestProveShieldWithAllDummyInputs(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	_, payerHash, owner, _ := proveTestOwner(t)

	deposit := uint64(100)
	tx := ProofTransactionRequest{
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		PublicAmountMode:         publicAmountShield,
		PublicSolAmount:          &deposit,
		EncryptedUtxos:           "00",
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
		Outputs: []ProofUtxoRequest{
			solOutput(owner, 60, 2000),
			solOutput(owner, 40, 2001),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}
