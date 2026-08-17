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
	ownerKeyHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	payerHash = new(big.Int).Set(ownerKeyHash)
	nullifierSecret = big.NewInt(12345)
	spendKey, err := protocol.NewSpendKey(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err = protocol.OwnerHash(ownerKeyHash, spendKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	return payerPubkey, payerHash, owner, nullifierSecret
}

func solOutput(owner *big.Int, amount, blinding int64) ProofUtxoRequest {
	var ownerPubkey [32]byte
	for i := range ownerPubkey {
		ownerPubkey[i] = byte(i + 1)
	}
	return ProofUtxoRequest{
		Domain:               proofFieldInput(big.NewInt(protocol.UtxoDomain)),
		Owner:                proofFieldInput(owner),
		OwnerSolanaPubkey:    parse.BytesHex(ownerPubkey[:]),
		OwnerNullifierSecret: proofFieldInput(big.NewInt(12345)),
		Asset:                proofFieldInput(protocol.SolAsset()),
		Amount:               proofFieldInput(big.NewInt(amount)),
		Blinding:             proofFieldInput(big.NewInt(blinding)),
		DataHash:             proofFieldInput(big.NewInt(0)),
		ZoneDataHash:         proofFieldInput(big.NewInt(0)),
		ZoneProgramID:        proofFieldInput(big.NewInt(0)),
	}
}

func proveAndVerify(t *testing.T, shape protocol.Shape, tx ProofTransactionRequest, payerHash *big.Int) {
	t.Helper()
	ps, err := Setup(shape)
	if err != nil {
		t.Fatal(err)
	}
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	assignment := built.witness
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

	tx := ProofTransactionRequest{
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		InterfaceTransfers: []InterfaceTransferRequest{{
			IsDeposit:   true,
			Amount:      100,
			UserAccount: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		}},
		EncryptedUtxos: "00",
		DataHash:       proofFieldInput(big.NewInt(0)),
		ZoneDataHash:   proofFieldInput(big.NewInt(0)),
		Outputs: []ProofUtxoRequest{
			solOutput(owner, 60, 2000),
			solOutput(owner, 40, 2001),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}

func TestProveMixedDirectionInterfaceTransfers(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := sampleTransactionRequest(shape)
	if err != nil {
		t.Fatal(err)
	}
	splAsset := testSplAsset(t, testMintA)
	tx.Inputs[1].Utxo.Asset = proofFieldInput(splAsset)
	tx.Outputs[1].Asset = proofFieldInput(splAsset)
	tx.Outputs[0].Amount = proofFieldInput(big.NewInt(25))
	tx.Outputs[1].Amount = proofFieldInput(big.NewInt(13))
	refreshStateEntry(t, &tx, 1)
	tx.InterfaceTransfers = []InterfaceTransferRequest{
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      7,
			UserAccount: stringsOfByte(0x41),
			PoolAccount: stringsOfByte(0x61),
		},
		{
			IsDeposit:   true,
			Amount:      5,
			UserAccount: stringsOfByte(0x21),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}

func TestProveSixSameAssetInterfaceTransfers(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	tx, payerHash, err := sampleTransactionRequest(shape)
	if err != nil {
		t.Fatal(err)
	}
	splAsset := testSplAsset(t, testMintA)
	tx.Inputs[0].Utxo.Asset = proofFieldInput(splAsset)
	for i := range tx.Outputs {
		tx.Outputs[i].Asset = proofFieldInput(splAsset)
	}
	tx.Outputs[0].Amount = proofFieldInput(big.NewInt(13))
	tx.Outputs[1].Amount = proofFieldInput(big.NewInt(9))
	refreshStateEntry(t, &tx, 0)
	tx.InterfaceTransfers = []InterfaceTransferRequest{
		{
			IsSpl:       true,
			IsDeposit:   true,
			Asset:       testMintA,
			Amount:      5,
			UserAccount: stringsOfByte(0x41),
			PoolAccount: stringsOfByte(0x61),
		},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      2,
			UserAccount: stringsOfByte(0x42),
			PoolAccount: stringsOfByte(0x62),
		},
		{
			IsSpl:       true,
			IsDeposit:   true,
			Asset:       testMintA,
			Amount:      4,
			UserAccount: stringsOfByte(0x43),
			PoolAccount: stringsOfByte(0x63),
		},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      3,
			UserAccount: stringsOfByte(0x44),
			PoolAccount: stringsOfByte(0x64),
		},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      1,
			UserAccount: stringsOfByte(0x45),
			PoolAccount: stringsOfByte(0x65),
		},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      1,
			UserAccount: stringsOfByte(0x46),
			PoolAccount: stringsOfByte(0x66),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}

func TestProveThreeDistinctPublicAssets(t *testing.T) {
	shape := protocol.Shape{NInputs: 3, NOutputs: 3}
	tx, payerHash, err := sampleTransactionRequest(shape)
	if err != nil {
		t.Fatal(err)
	}
	assetA := testSplAsset(t, testMintA)
	assetB := testSplAsset(t, testMintB)
	tx.Inputs[1].Utxo.Asset = proofFieldInput(assetA)
	tx.Inputs[2].Utxo.Asset = proofFieldInput(assetB)
	tx.Outputs[1].Asset = proofFieldInput(assetA)
	tx.Outputs[2].Asset = proofFieldInput(assetB)
	tx.Outputs[0].Amount = proofFieldInput(big.NewInt(35))
	tx.Outputs[1].Amount = proofFieldInput(big.NewInt(23))
	tx.Outputs[2].Amount = proofFieldInput(big.NewInt(32))
	refreshStateEntry(t, &tx, 1)
	refreshStateEntry(t, &tx, 2)
	tx.InterfaceTransfers = []InterfaceTransferRequest{
		{IsDeposit: true, Amount: 5, UserAccount: stringsOfByte(0x21)},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      7,
			UserAccount: stringsOfByte(0x41),
			PoolAccount: stringsOfByte(0x61),
		},
		{
			IsSpl:       true,
			IsDeposit:   true,
			Asset:       testMintB,
			Amount:      2,
			UserAccount: stringsOfByte(0x42),
			PoolAccount: stringsOfByte(0x62),
		},
	}

	proveAndVerify(t, shape, tx, payerHash)
}

func testSplAsset(t *testing.T, mintHex string) *big.Int {
	t.Helper()
	mint, err := parse.Hex32(mintHex)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := protocol.SolanaPkField(mint)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

func stringsOfByte(value byte) string {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = value
	}
	return parse.BytesHex(bytes)
}
