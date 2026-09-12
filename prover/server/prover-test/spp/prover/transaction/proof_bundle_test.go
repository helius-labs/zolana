package transaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
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

func TestBuildProofAssignmentRejectsRingFields(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	for _, tc := range []struct {
		name   string
		mutate func(tx *ProofTransactionRequest)
	}{
		{"tx data_hash", func(tx *ProofTransactionRequest) { tx.DataHash = proofFieldInput(big.NewInt(1)) }},
		{"tx ring_data_hash", func(tx *ProofTransactionRequest) { tx.RingDataHash = proofFieldInput(big.NewInt(1)) }},
		{"output data_hash", func(tx *ProofTransactionRequest) { tx.Outputs[0].DataHash = proofFieldInput(big.NewInt(1)) }},
		{"output ring_data_hash", func(tx *ProofTransactionRequest) { tx.Outputs[0].RingDataHash = proofFieldInput(big.NewInt(1)) }},
		{"output ring_program_id", func(tx *ProofTransactionRequest) { tx.Outputs[0].RingProgramID = proofFieldInput(big.NewInt(1)) }},
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
			name: "SOL leg with spl interface bump",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = []InterfaceTransferRequest{{
					Amount:           1,
					SplInterfaceBump: 1,
					UserAccount:      strings.Repeat("11", 32),
				}}
			},
			wantErr: "interface_transfers[0].spl_interface_bump must be zero for SOL",
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
			RingDataHash:  proofFieldInput(big.NewInt(0)),
			RingProgramID: proofFieldInput(big.NewInt(0)),
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
		RingDataHash:  "0x00",
		RingProgramID: "0x00",
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

// TestProofUtxoJSONUsesRingFields pins the JSON tags of the ring fields: each
// key must land in its own struct field (a swapped tag would surface as the
// wrong field name in the rejection error), and zero values must parse. The
// default transact pipeline rejects non-zero ring fields outright.
func TestProofUtxoJSONUsesRingFields(t *testing.T) {
	const baseJSON = `{
		"domain":"0x01",
		"owner":"0x02",
		"asset":"0x03",
		"amount":"0x04",
		"blinding":"0x05",
		"data_hash":"%s",
		"ring_data_hash":"%s",
		"ring_program_id":"%s"
	}`

	var request ProofUtxoRequest
	if err := json.Unmarshal([]byte(fmt.Sprintf(baseJSON, "0x00", "0x00", "0x00")), &request); err != nil {
		t.Fatal(err)
	}
	if _, err := parseProofUtxo(request, nil); err != nil {
		t.Fatalf("zero ring fields should parse: %v", err)
	}

	for _, tc := range []struct {
		field  string
		values [3]string
	}{
		{"data_hash", [3]string{"0x06", "0x00", "0x00"}},
		{"ring_data_hash", [3]string{"0x00", "0x07", "0x00"}},
		{"ring_program_id", [3]string{"0x00", "0x00", "0x08"}},
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

const canonicalExternalDataHash = "002569689bff7ef057bf95d5436d9dba68b906eec4255c9008ed23db042092f4"

func canonicalExternalDataFixture() externalDataPreimage {
	data := externalDataPreimage{
		InstructionDiscriminator: 16,
		ExpiryUnixTs:             1234567890,
		InterfaceTransfers: []resolvedInterfaceTransfer{
			{amount: 1234567890, asset: protocol.SolInterface},
			{isSpl: true, isDeposit: true, amount: 987654321, splInterfaceBump: 255},
		},
		Outputs: []resolvedOutput{
			{
				utxoHash: [32]byte{31: 1},
				hasData:  true,
				data: []byte{
					0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
					0x88, 0x89, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				},
			},
			{utxoHash: [32]byte{31: 2}},
		},
	}
	for i := range data.TxViewingPk {
		data.TxViewingPk[i] = byte(0x90 + i)
	}
	for i := range data.Salt {
		data.Salt[i] = byte(0xf0 + i)
	}
	for i := 0; i < 32; i++ {
		data.InterfaceTransfers[0].userAccount[i] = byte(0x20 + i)
		data.InterfaceTransfers[1].asset[i] = byte(0x60 + i)
		data.InterfaceTransfers[1].userAccount[i] = byte(0x40 + i)
		data.Outputs[0].ownerTag[i] = byte(i)
		data.Outputs[1].ownerTag[i] = byte(i)
	}
	return data
}

func TestExternalDataFieldHashMatchesCanonicalParityFixture(t *testing.T) {
	data := canonicalExternalDataFixture()

	got := externalDataFieldHash(data)
	if parse.FieldHex(got) != canonicalExternalDataHash {
		t.Fatalf("external data hash = %s, want %s", parse.FieldHex(got), canonicalExternalDataHash)
	}

	withDifferentExpiry := data
	withDifferentExpiry.ExpiryUnixTs ^= 1
	if parse.FieldHex(externalDataFieldHash(withDifferentExpiry)) == canonicalExternalDataHash {
		t.Fatal("external_data_hash did not change when expiry_unix_ts changed")
	}
}

func TestExternalDataPrefixMatchesTransactExternalDataLayout(t *testing.T) {
	data := canonicalExternalDataFixture()
	sol := data.InterfaceTransfers[0]
	spl := data.InterfaceTransfers[1]

	var want []byte
	want = append(want, 0xd2, 0x02, 0x96, 0x49, 0, 0, 0, 0)
	want = append(want, data.TxViewingPk[:]...)
	want = append(want, data.Salt[:]...)
	want = append(want, 2)
	want = append(want, 1, 0xd2, 0x02, 0x96, 0x49, 0, 0, 0, 0)
	want = append(want, 2, 0xb1, 0x68, 0xde, 0x3a, 0, 0, 0, 0, 255)
	want = append(want, 0)
	want = append(want, 0)
	want = append(want, 2)
	want = append(want, data.Outputs[0].utxoHash[:]...)
	want = append(want, 0)
	want = append(want, data.Outputs[0].ownerTag[:]...)
	want = append(want, 1, 16, 0)
	want = append(want, data.Outputs[0].data...)
	want = append(want, data.Outputs[1].utxoHash[:]...)
	want = append(want, 0)
	want = append(want, data.Outputs[1].ownerTag[:]...)
	want = append(want, 0)
	want = append(want, 0)

	got := externalDataPrefixBytes(data)
	if !bytes.Equal(got, want) {
		t.Fatalf("external data prefix =\n%x\nwant\n%x", got, want)
	}

	wantHash := protocol.Sha256BEField(
		[]byte{12},
		want,
		protocol.SolInterface[:],
		sol.userAccount[:],
		spl.asset[:],
		spl.userAccount[:],
	)
	if externalDataFieldHash(data).Cmp(wantHash) != 0 {
		t.Fatal("external_data_hash is not sha256BE(discriminator || prefix || [asset, user] per leg)")
	}
}

func TestExternalDataPrefixEncodesMessages(t *testing.T) {
	message := resolvedMessage{viewTag: [32]byte{7}, data: []byte{0xaa, 0xbb, 0xcc}}
	data := externalDataPreimage{Messages: []resolvedMessage{message}}

	var wantTail []byte
	wantTail = append(wantTail, 1)
	wantTail = append(wantTail, message.viewTag[:]...)
	wantTail = append(wantTail, 3, 0)
	wantTail = append(wantTail, message.data...)

	got := externalDataPrefixBytes(data)
	if !bytes.HasSuffix(got, wantTail) {
		t.Fatalf("external data prefix =\n%x\ndoes not end with\n%x", got, wantTail)
	}
	if externalDataFieldHash(data).Cmp(externalDataFieldHash(externalDataPreimage{})) == 0 {
		t.Fatal("external_data_hash did not bind messages")
	}
}

func TestExternalDataFieldHashBindsOrderedTaggedInterfaceTransfers(t *testing.T) {
	base := externalDataPreimage{
		InterfaceTransfers: []resolvedInterfaceTransfer{
			{amount: 5, asset: protocol.SolInterface, userAccount: [32]byte{1}},
			{isSpl: true, isDeposit: true, amount: 7, splInterfaceBump: 254, asset: [32]byte{3}, userAccount: [32]byte{2}},
		},
	}
	baseHash := externalDataFieldHash(base)

	for _, tc := range []struct {
		name   string
		mutate func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer
	}{
		{"order", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			return []resolvedInterfaceTransfer{legs[1], legs[0]}
		}},
		{"count", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			return legs[:1]
		}},
		{"variant", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[0].isSpl = true
			return legs
		}},
		{"direction", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[0].isDeposit = true
			return legs
		}},
		{"amount", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[0].amount ^= 1
			return legs
		}},
		{"spl interface bump", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[1].splInterfaceBump ^= 1
			return legs
		}},
		{"asset", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[1].asset[0] ^= 1
			return legs
		}},
		{"sol interface address", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[0].asset[0] ^= 1
			return legs
		}},
		{"user account", func(legs []resolvedInterfaceTransfer) []resolvedInterfaceTransfer {
			legs[0].userAccount[0] ^= 1
			return legs
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			mutated.InterfaceTransfers = tc.mutate(slices.Clone(base.InterfaceTransfers))
			if externalDataFieldHash(mutated).Cmp(baseHash) == 0 {
				t.Fatalf("external_data_hash did not bind interface transfer %s", tc.name)
			}
		})
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

	ringDataHashPresent := base
	ringDataHashPresent.RingDataHashPresent = true
	if externalDataFieldHash(ringDataHashPresent).Cmp(baseHash) == 0 {
		t.Fatal("external_data_hash collapsed absent ring_data_hash and present zero ring_data_hash")
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
			IsSpl:            true,
			IsDeposit:        true,
			Asset:            testMintA,
			Amount:           8,
			SplInterfaceBump: 250,
			UserAccount:      strings.Repeat("41", 32),
		},
		{
			IsSpl:            true,
			Asset:            testMintA,
			Amount:           3,
			SplInterfaceBump: 250,
			UserAccount:      strings.Repeat("42", 32),
		},
	}
	normalized, err := normalizedInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 2 ||
		normalized[0].UserAccount == normalized[1].UserAccount ||
		normalized[0].SplInterfaceBump != 250 ||
		normalized[1].SplInterfaceBump != 250 {
		t.Fatalf("normalized interface transfers lost settlement identity: %+v", normalized)
	}

	resolved, err := resolveInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	separateHash := externalDataFieldHash(externalDataPreimage{InterfaceTransfers: resolved})
	aggregatedHash := externalDataFieldHash(externalDataPreimage{
		InterfaceTransfers: []resolvedInterfaceTransfer{{
			isSpl:            true,
			isDeposit:        true,
			amount:           5,
			splInterfaceBump: resolved[0].splInterfaceBump,
			asset:            resolved[0].asset,
			userAccount:      resolved[0].userAccount,
		}},
	})
	if separateHash.Cmp(aggregatedHash) == 0 {
		t.Fatal("external_data_hash collapsed separate same-asset interface transfers")
	}
}

func TestProofUtxoRootIndices(t *testing.T) {
	got, err := proofUtxoRootIndices(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != [protocol.InputTrees]uint16{} {
		t.Fatalf("default root indices = %v, want all zero", got)
	}

	// One index per tree slot, in slot order.
	slotIndices := [protocol.InputTrees]uint16{3, 4, 5, 6, 7}
	got, err = proofUtxoRootIndices(slotIndices[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != slotIndices {
		t.Fatalf("root indices = %v, want %v", got, slotIndices)
	}

	// A per-input length is no longer accepted: the indices are per tree slot.
	_, err = proofUtxoRootIndices([]uint16{1, 2})
	if err == nil || !strings.Contains(err.Error(), "length 2 does not match the 5 tree slots") {
		t.Fatalf("error = %v", err)
	}
}

// TestBuildProofAssignmentBindsTreeIDs pins that the request's tree ids reach
// both the utxo hashes and the published slots: inputs are hashed under
// input_tree_id, only slot 0 is populated, and every input selects it.
func TestBuildProofAssignmentBindsTreeIDs(t *testing.T) {
	const inputTreeID, outputTreeID = 7, 11
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	tx.InputTreeID = inputTreeID
	tx.OutputTreeID = outputTreeID
	for i := range tx.Inputs {
		refreshStateEntry(t, &tx, i)
	}

	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	slots := built.publicInputs.TreeSlots
	if len(slots) != protocol.InputTrees {
		t.Fatalf("tree slots = %d, want %d", len(slots), protocol.InputTrees)
	}
	if slots[0].ID.Cmp(big.NewInt(inputTreeID)) != 0 {
		t.Fatalf("slot 0 id = %s, want %d", slots[0].ID, inputTreeID)
	}
	if slots[0].UtxoRoot.Sign() == 0 || slots[0].NullifierRoot.Sign() == 0 {
		t.Fatal("slot 0 must publish both roots: the circuit refuses to select a zero-rooted slot")
	}
	for i, slot := range slots[1:] {
		if slot.ID.Sign() != 0 || slot.UtxoRoot.Sign() != 0 || slot.NullifierRoot.Sign() != 0 {
			t.Fatalf("unused slot %d must be all zero, got %+v", i+1, slot)
		}
	}
	if built.publicInputs.OutputTreeID.Cmp(big.NewInt(outputTreeID)) != 0 {
		t.Fatalf("output tree id = %s, want %d", built.publicInputs.OutputTreeID, outputTreeID)
	}
	witness, ok := built.witness.(*customring.CustomRingEddsaOnlyCircuit)
	if !ok {
		t.Fatalf("witness type = %T", built.witness)
	}
	for i, input := range witness.Private.Inputs {
		if spptest.AsBigInt(input.TreeSlot).Sign() != 0 {
			t.Fatalf("input %d selects slot %v, want the single populated slot 0", i, input.TreeSlot)
		}
	}
	solveAssignment(t, shape, built)
}

// A state entry hashed under the wrong tree id must not prove: the builder
// rebinds the input hash to input_tree_id, so the leaf lookup misses.
func TestBuildProofAssignmentRejectsStateEntryFromAnotherTree(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	// benchmarkTransaction hashed the state entry under tree 0; moving the
	// transaction to tree 7 without rehashing must be rejected.
	tx.InputTreeID = 7

	_, err = buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "is not present in state_entries") {
		t.Fatalf("error = %v", err)
	}
}
