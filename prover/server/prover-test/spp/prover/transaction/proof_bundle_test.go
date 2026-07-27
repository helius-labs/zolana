package transaction

import (
	"encoding/json"
	"fmt"
	"math"
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
			tx, payerHash, err := benchmarkTransaction(shape)
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
	tx, payerHash, err := benchmarkTransaction(shape)
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

func TestBuildProofAssignmentRejectsBadInterfaceTransferRequests(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	tests := []struct {
		name    string
		mutate  func(*ProofTransactionRequest)
		wantErr string
	}{
		{
			name: "transfer count exceeds u8 encoding",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = make([]InterfaceTransferRequest, MaxInterfaceTransfers+1)
				for i := range tx.InterfaceTransfers {
					tx.InterfaceTransfers[i].Amount = 1
				}
			},
			wantErr: "interface_transfers length 256 exceeds u8 encoding maximum 255",
		},
		{
			name: "zero amount",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = []InterfaceTransferRequest{{Amount: 0}}
			},
			wantErr: "interface_transfers[0].amount must be nonzero",
		},
		{
			name: "missing spl mint",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = []InterfaceTransferRequest{{IsSpl: true, Amount: 1}}
			},
			wantErr: "interface_transfers[0].asset",
		},
		{
			name: "missing user account",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = []InterfaceTransferRequest{{Amount: 1}}
			},
			wantErr: "interface_transfers[0].user_account",
		},
		{
			name: "missing SPL pool account",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = []InterfaceTransferRequest{{
					IsSpl:       true,
					Asset:       testMintA,
					Amount:      1,
					UserAccount: strings.Repeat("11", 32),
				}}
			},
			wantErr: "interface_transfers[0].pool_account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx, payerHash, err := benchmarkTransaction(shape)
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
	// Known-answer vector for the canonical Rust ExternalDataHash layout:
	// counted direction-tagged transfers, absent optional zone hashes, the
	// transaction encryption context, counted resolved outputs with Some/None
	// data, and an empty counted message section.
	data := externalDataPreimage{
		InstructionDiscriminator: 0x0d,
		ExpiryUnixTs:             0x1122334455667788,
		InterfaceTransfers: []resolvedInterfaceTransfer{
			{amount: 0x0102030405060708},
			{isSpl: true, isDeposit: true, amount: 0x1112131415161718},
		},
		Outputs: []resolvedOutput{
			{hasData: true, data: []byte{0xaa, 0xbb, 0xcc}},
			{},
		},
	}
	for i := range data.Outputs[0].ownerTag {
		data.InterfaceTransfers[0].userAccount[i] = byte(0x20 + i)
		data.InterfaceTransfers[1].userAccount[i] = byte(0x40 + i)
		data.InterfaceTransfers[1].poolAccount[i] = byte(0x60 + i)
		data.Outputs[0].utxoHash[i] = byte(i)
		data.Outputs[0].ownerTag[i] = byte(0x80 + i)
		data.Outputs[1].utxoHash[i] = byte(0xa0 + i)
		data.Outputs[1].ownerTag[i] = byte(0xc0 + i)
	}

	got := externalDataFieldHash(data)
	const want = "002dd852de9b27e16b074ab1fe930f1ff5fcd8cf21aef89a3bd430e83d7e902f"
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

func TestExternalDataFieldHashBindsOrderedTaggedInterfaceTransfers(t *testing.T) {
	userA := [32]byte{1}
	userB := [32]byte{2}
	pool := [32]byte{3}
	base := externalDataPreimage{
		InterfaceTransfers: []resolvedInterfaceTransfer{
			{amount: 5, userAccount: userA},
			{isSpl: true, isDeposit: true, amount: 7, userAccount: userB, poolAccount: pool},
		},
	}
	baseHash := externalDataFieldHash(base)

	reordered := base
	reordered.InterfaceTransfers = []resolvedInterfaceTransfer{
		base.InterfaceTransfers[1],
		base.InterfaceTransfers[0],
	}
	if externalDataFieldHash(reordered).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind interface transfer order")
	}

	oneTransfer := base
	oneTransfer.InterfaceTransfers = base.InterfaceTransfers[:1]
	if externalDataFieldHash(oneTransfer).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind interface transfer count")
	}

	differentTag := base
	differentTag.InterfaceTransfers = append(
		[]resolvedInterfaceTransfer(nil),
		base.InterfaceTransfers...,
	)
	differentTag.InterfaceTransfers[0].isSpl = true
	differentTag.InterfaceTransfers[0].poolAccount = pool
	if externalDataFieldHash(differentTag).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind interface transfer tag")
	}

	differentDirection := base
	differentDirection.InterfaceTransfers = append(
		[]resolvedInterfaceTransfer(nil),
		base.InterfaceTransfers...,
	)
	differentDirection.InterfaceTransfers[0].isDeposit = true
	if externalDataFieldHash(differentDirection).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind interface transfer direction")
	}

	differentRecipient := base
	differentRecipient.InterfaceTransfers = append(
		[]resolvedInterfaceTransfer(nil),
		base.InterfaceTransfers...,
	)
	differentRecipient.InterfaceTransfers[0].userAccount[0] ^= 1
	if externalDataFieldHash(differentRecipient).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind interface transfer recipient")
	}
}

func TestExternalDataFieldHashBindsEncryptionContextAndOptionalHashPresence(t *testing.T) {
	base := externalDataPreimage{
		TxViewingPk: [33]byte{1},
		Salt:        [16]byte{2},
	}
	baseHash := externalDataFieldHash(base)

	differentPk := base
	differentPk.TxViewingPk[0] ^= 1
	if externalDataFieldHash(differentPk).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind tx_viewing_pk")
	}

	differentSalt := base
	differentSalt.Salt[0] ^= 1
	if externalDataFieldHash(differentSalt).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash did not bind salt")
	}

	dataHashPresent := base
	dataHashPresent.DataHashPresent = true
	if externalDataFieldHash(dataHashPresent).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash collapsed absent data_hash and present zero data_hash")
	}

	zoneDataHashPresent := base
	zoneDataHashPresent.ZoneDataHashPresent = true
	if externalDataFieldHash(zoneDataHashPresent).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash collapsed absent zone_data_hash and present zero zone_data_hash")
	}
}

func TestResolveOutputsMatchesSingleSenderBundle(t *testing.T) {
	ownerTag := [32]byte{9}
	outputs, err := resolveOutputs(
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		ownerTag,
		[]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 2 {
		t.Fatalf("outputs length = %d, want 2", len(outputs))
	}
	for i, output := range outputs {
		if output.ownerTag != ownerTag {
			t.Fatalf("output %d owner tag = %x, want %x", i, output.ownerTag, ownerTag)
		}
	}
	if !outputs[0].hasData || len(outputs[0].data) != 0 {
		t.Fatal("first output must carry Some(empty) for an empty sender bundle")
	}
	if outputs[1].hasData {
		t.Fatal("second output must carry None")
	}

	withSomeEmpty := externalDataFieldHash(externalDataPreimage{Outputs: outputs})
	outputs[0].hasData = false
	withNone := externalDataFieldHash(externalDataPreimage{Outputs: outputs})
	if withSomeEmpty.Cmp(withNone) == 0 {
		t.Fatal("external_data_hash collapsed Some(empty) and None")
	}
}

func TestInstructionOutputHashesExcludeCircuitPadding(t *testing.T) {
	real := big.NewInt(1)
	dummy := big.NewInt(2)
	got, err := instructionOutputHashes([]*big.Int{real, dummy}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != real {
		t.Fatalf("instruction output hashes = %v, want only the real hash", got)
	}

	ownerTag := [32]byte{9}
	realOutputs, err := resolveOutputs(got, ownerTag, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	withPadding, err := resolveOutputs([]*big.Int{real, dummy}, ownerTag, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	realHash := externalDataFieldHash(externalDataPreimage{Outputs: realOutputs})
	paddedHash := externalDataFieldHash(externalDataPreimage{Outputs: withPadding})
	if realHash.Cmp(paddedHash) == 0 {
		t.Fatal("external_data_hash did not distinguish real outputs from circuit padding")
	}

	if _, err := instructionOutputHashes([]*big.Int{real}, 2); err == nil {
		t.Fatal("out-of-range real output count must be rejected")
	}
}

func TestInterfaceTransferRequestJSONSupportsFullU64(t *testing.T) {
	var transfer InterfaceTransferRequest
	if err := json.Unmarshal([]byte(`{"is_deposit":true,"amount":18446744073709551615}`), &transfer); err != nil {
		t.Fatal(err)
	}
	if !transfer.IsDeposit || transfer.Amount != math.MaxUint64 {
		t.Fatalf("decoded interface transfer = %+v", transfer)
	}
	if err := json.Unmarshal([]byte(`{"amount":-1}`), &transfer); err == nil {
		t.Fatal("negative interface-transfer magnitude must be rejected")
	}
}

func TestSameAssetTransfersRemainSeparateInHashAndBundleOutput(t *testing.T) {
	requests := []InterfaceTransferRequest{
		{
			IsSpl:       true,
			IsDeposit:   true,
			Asset:       testMintA,
			Amount:      8,
			UserAccount: strings.Repeat("41", 32),
			PoolAccount: strings.Repeat("61", 32),
		},
		{
			IsSpl:       true,
			Asset:       testMintA,
			Amount:      3,
			UserAccount: strings.Repeat("42", 32),
			PoolAccount: strings.Repeat("62", 32),
		},
	}
	normalized, err := normalizedInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 2 ||
		normalized[0].UserAccount == normalized[1].UserAccount ||
		normalized[0].PoolAccount == normalized[1].PoolAccount {
		t.Fatalf("normalized interface transfers lost settlement identity: %+v", normalized)
	}

	resolved, err := resolveInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	separateHash := externalDataFieldHash(externalDataPreimage{InterfaceTransfers: resolved})
	aggregatedHash := externalDataFieldHash(externalDataPreimage{
		InterfaceTransfers: []resolvedInterfaceTransfer{{
			isSpl:       true,
			isDeposit:   true,
			amount:      5,
			userAccount: resolved[0].userAccount,
			poolAccount: resolved[0].poolAccount,
		}},
	})
	if separateHash.Cmp(aggregatedHash) == 0 {
		t.Fatal("external_data_hash collapsed separate same-asset interface transfers")
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
