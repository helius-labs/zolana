package transaction

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

func TestBuildProofAssignmentRejectsOverCapacityArity(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	signerHash := big.NewInt(0)

	// Fewer inputs/outputs than the shape are allowed (padded with dummies); only
	// exceeding the shape's capacity is an error.
	_, _, _, _, _, err := buildProofAssignment(shape, ProofTransactionRequest{
		Inputs:  make([]ProofInputRequest, shape.NInputs+1),
		Outputs: make([]ProofUtxoRequest, shape.NOutputs),
	}, signerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "allows at most 1 inputs, got 2") {
		t.Fatalf("input arity error = %v", err)
	}

	_, _, _, _, _, err = buildProofAssignment(shape, ProofTransactionRequest{
		Inputs:  make([]ProofInputRequest, shape.NInputs),
		Outputs: make([]ProofUtxoRequest, shape.NOutputs+1),
	}, signerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "allows at most 2 outputs, got 3") {
		t.Fatalf("output arity error = %v", err)
	}
}

func TestBuildProofAssignmentRejectsMixedNullifierSecrets(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, signerHash, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[1].NullifierSecret = proofFieldInput(big.NewInt(999))

	_, _, _, _, _, err = buildProofAssignment(shape, tx, signerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "nullifier_secret differs from input 0") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildProofAssignmentRejectsBadPublicAmountRequests(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	validMint := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	amount := uint64(1)

	tests := []struct {
		name    string
		mutate  func(*ProofTransactionRequest)
		wantErr string
	}{
		{
			name: "invalid mode",
			mutate: func(tx *ProofTransactionRequest) {
				tx.PublicAmountMode = 3
			},
			wantErr: "invalid public_amount_mode",
		},
		{
			name: "transfer sol amount",
			mutate: func(tx *ProofTransactionRequest) {
				tx.PublicSolAmount = &amount
			},
			wantErr: "transfer mode carries public settlement",
		},
		{
			name: "transfer spl amount",
			mutate: func(tx *ProofTransactionRequest) {
				tx.PublicSplAmount = &amount
				tx.PublicSplAssetPubkey = validMint
			},
			wantErr: "transfer mode carries public settlement",
		},
		{
			name: "shield relayer fee",
			mutate: func(tx *ProofTransactionRequest) {
				tx.PublicAmountMode = publicAmountShield
				tx.RelayerFee = 1
			},
			wantErr: "shield mode carries relayer fee",
		},
		{
			name: "missing spl mint",
			mutate: func(tx *ProofTransactionRequest) {
				tx.PublicAmountMode = publicAmountShield
				tx.PublicSplAmount = &amount
			},
			wantErr: "public_spl_asset_pubkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx, signerHash, err := benchmarkTransaction(shape)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&tx)

			_, _, _, _, _, err = buildProofAssignment(shape, tx, signerHash, proofBuildOptions{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseProofInputRequiresOwnerComponents(t *testing.T) {
	_, err := parseProofInput(ProofInputRequest{
		Utxo: ProofUtxoRequest{
			Domain:        proofFieldInput(big.NewInt(1)),
			Owner:         proofFieldInput(big.NewInt(2)),
			AssetID:       proofFieldInput(big.NewInt(3)),
			AssetAmount:   proofFieldInput(big.NewInt(4)),
			Blinding:      proofFieldInput(big.NewInt(5)),
			DataHash:      proofFieldInput(big.NewInt(0)),
			ZoneDataHash:  proofFieldInput(big.NewInt(0)),
			ZoneProgramID: proofFieldInput(big.NewInt(0)),
		},
		NullifierSecret: proofFieldInput(big.NewInt(9)),
	})
	if err == nil || !strings.Contains(err.Error(), "owner components are required") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseProofUtxoNormalizesRequestFieldsAsPrefixedHex(t *testing.T) {
	parsed, err := parseProofUtxo(ProofUtxoRequest{
		Domain:        "0x0a",
		Owner:         "0x01",
		AssetID:       "0x02",
		AssetAmount:   "0x03",
		Blinding:      "0x04",
		DataHash:      "0x00",
		ZoneDataHash:  "0x00",
		ZoneProgramID: "0x00",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.normalized.Domain != proofFieldInput(big.NewInt(10)) {
		t.Fatalf("normalized domain = %q", parsed.normalized.Domain)
	}
	if _, err := parse.Field(parsed.normalized.Domain); err != nil {
		t.Fatalf("normalized field should round-trip through request parser: %v", err)
	}
}

func TestProofUtxoJSONUsesZoneFields(t *testing.T) {
	var request ProofUtxoRequest
	if err := json.Unmarshal([]byte(`{
		"domain":"0x01",
		"owner":"0x02",
		"asset_id":"0x03",
		"asset_amount":"0x04",
		"blinding":"0x05",
		"data_hash":"0x06",
		"zone_data_hash":"0x07",
		"zone_program_id":"0x08"
	}`), &request); err != nil {
		t.Fatal(err)
	}

	parsed, err := parseProofUtxo(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.utxo.ZoneDataHash.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("zone data hash = %s", parsed.utxo.ZoneDataHash)
	}
	if parsed.utxo.ZoneProgramID.Cmp(big.NewInt(8)) != 0 {
		t.Fatalf("zone program id = %s", parsed.utxo.ZoneProgramID)
	}
	if parsed.normalized.ZoneDataHash != proofFieldInput(big.NewInt(7)) {
		t.Fatalf("normalized zone data hash = %q", parsed.normalized.ZoneDataHash)
	}
	if parsed.normalized.ZoneProgramID != proofFieldInput(big.NewInt(8)) {
		t.Fatalf("normalized zone program id = %q", parsed.normalized.ZoneProgramID)
	}
}

func TestExternalDataFieldHashMatchesVector(t *testing.T) {
	data := externalDataPreimage{
		InstructionDiscriminator: 0x0d,
		RelayerFee:               0x1234,
		ExpiryUnixTs:             0x1122334455667788,
		PublicSolAmount:          0x0102030405060708,
		PublicSplAmount:          0x1112131415161718,
		EncryptedUtxos:           []byte{0xaa, 0xbb, 0xcc},
	}
	for i := range data.SenderViewTag {
		data.SenderViewTag[i] = byte(i)
		data.UserSolAccount[i] = byte(0x20 + i)
		data.UserSplToken[i] = byte(0x40 + i)
		data.SplTokenInterface[i] = byte(0x60 + i)
	}

	got := externalDataFieldHash(data)
	const want = "00054bb92fedd78c3b5c592bf929a656d382cb9bff39094166d3e9a4ad15d89f"
	if parse.FieldHex(got) != want {
		t.Fatalf("external data hash = %s, want %s", parse.FieldHex(got), want)
	}
}

func TestProofRootIndices(t *testing.T) {
	got, err := proofRootIndices(nil, 2, "utxo_tree_root_index")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Fatalf("default root indices = %v", got)
	}

	got, err = proofRootIndices([]uint16{3, 4}, 2, "utxo_tree_root_index")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 3 || got[1] != 4 {
		t.Fatalf("root indices = %v", got)
	}

	_, err = proofRootIndices([]uint16{1}, 2, "utxo_tree_root_index")
	if err == nil || !strings.Contains(err.Error(), "length 1 does not match input count 2") {
		t.Fatalf("error = %v", err)
	}
}
