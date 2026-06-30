package transaction

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

func TestBuildProofAssignmentRejectsOverCapacityArity(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	payerHash := big.NewInt(0)

	// Fewer inputs/outputs than the shape are allowed (padded with dummies); only
	// exceeding the shape's capacity is an error.
	_, err := buildProofAssignment(shape, ProofTransactionRequest{
		Inputs:  make([]ProofInputRequest, shape.NInputs+1),
		Outputs: make([]ProofUtxoRequest, shape.NOutputs),
	}, payerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "allows at most 1 inputs, got 2") {
		t.Fatalf("input arity error = %v", err)
	}

	_, err = buildProofAssignment(shape, ProofTransactionRequest{
		Inputs:  make([]ProofInputRequest, shape.NInputs),
		Outputs: make([]ProofUtxoRequest, shape.NOutputs+1),
	}, payerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "allows at most 2 outputs, got 3") {
		t.Fatalf("output arity error = %v", err)
	}
}

func TestBuildProofAssignmentRejectsNonCanonicalShape(t *testing.T) {
	// 1 input / 2 outputs fits a 2-2 shape, but SPP derives the vkey from the
	// real counts and would verify with 1-2 — the proof could never pass
	// on-chain, so the build must fail.
	_, err := buildProofAssignment(protocol.Shape{NInputs: 2, NOutputs: 2}, ProofTransactionRequest{
		Inputs:  make([]ProofInputRequest, 1),
		Outputs: make([]ProofUtxoRequest, 2),
	}, big.NewInt(0), proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("non-canonical shape error = %v", err)
	}
}

func TestBuildProofAssignmentRejectsZoneFields(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	for _, tc := range []struct {
		name   string
		mutate func(tx *ProofTransactionRequest)
	}{
		{"tx data_hash", func(tx *ProofTransactionRequest) { tx.DataHash = proofFieldInput(big.NewInt(1)) }},
		{"tx zone_data_hash", func(tx *ProofTransactionRequest) { tx.ZoneDataHash = proofFieldInput(big.NewInt(1)) }},
		{"output data_hash", func(tx *ProofTransactionRequest) { tx.Outputs[0].DataHash = proofFieldInput(big.NewInt(1)) }},
		{"output zone_data_hash", func(tx *ProofTransactionRequest) { tx.Outputs[0].ZoneDataHash = proofFieldInput(big.NewInt(1)) }},
		{"output zone_program_id", func(tx *ProofTransactionRequest) { tx.Outputs[0].ZoneProgramID = proofFieldInput(big.NewInt(1)) }},
		{"input data_hash", func(tx *ProofTransactionRequest) { tx.Inputs[0].Utxo.DataHash = proofFieldInput(big.NewInt(1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, payerHash, err := benchmarkTransaction(shape, false)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&tx)
			_, err = buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
			if err == nil || !strings.Contains(err.Error(), "must be zero") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBuildProofAssignmentAcceptsDistinctNullifierSecrets(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape, false)
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[1].NullifierSecret = proofFieldInput(big.NewInt(999))
	refreshStateEntry(t, &tx, 1)

	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("distinct nullifier secrets must build: %v", err)
	}
	nullifiers := built.publicInputs.Nullifiers
	if nullifiers[0].Sign() == 0 || nullifiers[1].Sign() == 0 {
		t.Fatal("both inputs must publish real nullifiers")
	}
	if nullifiers[0].Cmp(nullifiers[1]) == 0 {
		t.Fatal("nullifiers must differ across inputs")
	}
	solveAssignment(t, shape, built)
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
			tx, payerHash, err := benchmarkTransaction(shape, false)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&tx)

			_, err = buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
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
			Asset:         proofFieldInput(big.NewInt(3)),
			Amount:        proofFieldInput(big.NewInt(4)),
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
		Asset:         "0x02",
		Amount:        "0x03",
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

// TestProofUtxoJSONUsesZoneFields pins the JSON tags of the zone fields: each
// key must land in its own struct field (a swapped tag would surface as the
// wrong field name in the rejection error), and zero values must parse. The
// default transact pipeline rejects non-zero zone fields outright.
func TestProofUtxoJSONUsesZoneFields(t *testing.T) {
	const baseJSON = `{
		"domain":"0x01",
		"owner":"0x02",
		"asset":"0x03",
		"amount":"0x04",
		"blinding":"0x05",
		"data_hash":"%s",
		"zone_data_hash":"%s",
		"zone_program_id":"%s"
	}`

	var request ProofUtxoRequest
	if err := json.Unmarshal([]byte(fmt.Sprintf(baseJSON, "0x00", "0x00", "0x00")), &request); err != nil {
		t.Fatal(err)
	}
	if _, err := parseProofUtxo(request, nil); err != nil {
		t.Fatalf("zero zone fields should parse: %v", err)
	}

	for _, tc := range []struct {
		field  string
		values [3]string
	}{
		{"data_hash", [3]string{"0x06", "0x00", "0x00"}},
		{"zone_data_hash", [3]string{"0x00", "0x07", "0x00"}},
		{"zone_program_id", [3]string{"0x00", "0x00", "0x08"}},
	} {
		var request ProofUtxoRequest
		blob := fmt.Sprintf(baseJSON, tc.values[0], tc.values[1], tc.values[2])
		if err := json.Unmarshal([]byte(blob), &request); err != nil {
			t.Fatal(err)
		}
		_, err := parseProofUtxo(request, nil)
		if err == nil || !strings.Contains(err.Error(), tc.field+" must be zero") {
			t.Fatalf("%s: error = %v", tc.field, err)
		}
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
	const want = "003cee91f18bdad1f50991823f95d10e840ab34792721e22dbda3eea4c014742"
	if parse.FieldHex(got) != want {
		t.Fatalf("external data hash = %s, want %s", parse.FieldHex(got), want)
	}

	// expiry_unix_ts is bound in external_data_hash (not private_tx_hash), so
	// changing it must change the hash.
	withDifferentExpiry := data
	withDifferentExpiry.ExpiryUnixTs ^= 1
	if parse.FieldHex(externalDataFieldHash(withDifferentExpiry)) == want {
		t.Fatal("external_data_hash did not change when expiry_unix_ts changed")
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
