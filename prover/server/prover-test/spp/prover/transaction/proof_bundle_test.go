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
			name: "transfer count exceeds protocol maximum",
			mutate: func(tx *ProofTransactionRequest) {
				tx.InterfaceTransfers = make([]InterfaceTransferRequest, MaxInterfaceTransfers+1)
				for i := range tx.InterfaceTransfers {
					tx.InterfaceTransfers[i].Amount = 1
				}
			},
			wantErr: "interface_transfers length 33 exceeds protocol maximum 32",
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
		{
			name: "SPL bump on SOL transfer",
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

func TestExternalDataHashMatchesRustWincodeVector(t *testing.T) {
	// This is the exact fixture in
	// sdk-libs/transaction/src/instructions/transact/external_data.rs. It covers both interface enum
	// shapes, both owner-tag enum shapes, Some/None, a message, and all four
	// committed-address positions.
	data := externalDataHashInput{
		instructionDiscriminator: 15,
		inputTree:                repeated32(2),
		outputTree:               repeated32(3),
		expiryUnixTs:             42,
		txViewingPk:              repeated33(26),
		salt:                     repeated16(27),
		interfaceTransfers: []interfaceTransferData{
			{
				kind:        interfaceTransferSolDeposit,
				amount:      1,
				userAccount: repeated32(20),
			},
			{
				kind:              interfaceTransferSplWithdrawal,
				amount:            2,
				splInterfaceBump:  255,
				userAccount:       repeated32(22),
				splTokenInterface: repeated32(23),
			},
		},
		dataHashPresent:     true,
		dataHash:            repeated32(24),
		ringDataHashPresent: true,
		ringDataHash:        repeated32(25),
		outputs: []transactOutputData{
			{
				utxoHash:    repeated32(28),
				ownerTag:    ownerTagData{kind: ownerTagInline, inline: repeated32(29)},
				dataPresent: true,
				data:        []byte{30, 31},
			},
			{
				utxoHash: repeated32(32),
				ownerTag: ownerTagData{
					kind:           ownerTagAccount,
					accountIndex:   7,
					accountAddress: repeated32(33),
				},
			},
		},
		messages: []transactMessageData{{viewTag: repeated32(34), data: []byte{35, 36}}},
	}

	prefix, err := encodeExternalDataPrefix(data)
	if err != nil {
		t.Fatal(err)
	}
	const wantPrefix = "2a000000000000001a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b02000100000000000000030200000000000000ff011818181818181818181818181818181818181818181818181818181818181818011919191919191919191919191919191919191919191919191919191919191919021c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c001d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d0102001e1f202020202020202020202020202020202020202020202020202020202020202001070001222222222222222222222222222222222222222222222222222222222222222202002324"
	if got := fmt.Sprintf("%x", prefix); got != wantPrefix {
		t.Fatalf("external-data prefix mismatch:\ngot  %s\nwant %s", got, wantPrefix)
	}

	wantHash := [32]byte{
		0, 136, 175, 175, 95, 241, 142, 109, 78, 140, 29, 136, 32, 94, 140, 36,
		228, 140, 241, 79, 128, 248, 18, 59, 248, 160, 28, 213, 99, 139, 161, 8,
	}
	if got := mustExternalDataHash(t, data); got != wantHash {
		t.Fatalf("external data hash = %x, want %x", got, wantHash)
	}

	withDifferentExpiry := data
	withDifferentExpiry.expiryUnixTs ^= 1
	if mustExternalDataHash(t, withDifferentExpiry) == wantHash {
		t.Fatal("external_data_hash did not bind expiry_unix_ts")
	}

	withDifferentOwnerAddress := data
	withDifferentOwnerAddress.outputs = append([]transactOutputData(nil), data.outputs...)
	withDifferentOwnerAddress.outputs[1].ownerTag.accountAddress[0] ^= 1
	if mustExternalDataHash(t, withDifferentOwnerAddress) == wantHash {
		t.Fatal("external_data_hash did not bind account-backed output owner address")
	}
}

func TestExternalDataHashBindsOrderedTaggedInterfaceTransfers(t *testing.T) {
	userA := [32]byte{1}
	userB := [32]byte{2}
	splInterface := [32]byte{3}
	base := externalDataHashInput{
		interfaceTransfers: []interfaceTransferData{
			{kind: interfaceTransferSolWithdrawal, amount: 5, userAccount: userA},
			{
				kind:              interfaceTransferSplDeposit,
				amount:            7,
				splInterfaceBump:  9,
				userAccount:       userB,
				splTokenInterface: splInterface,
			},
		},
	}
	baseHash := mustExternalDataHash(t, base)

	reordered := base
	reordered.interfaceTransfers = []interfaceTransferData{
		base.interfaceTransfers[1],
		base.interfaceTransfers[0],
	}
	if mustExternalDataHash(t, reordered) == baseHash {
		t.Fatal("external_data_hash did not bind interface transfer order")
	}

	oneTransfer := base
	oneTransfer.interfaceTransfers = base.interfaceTransfers[:1]
	if mustExternalDataHash(t, oneTransfer) == baseHash {
		t.Fatal("external_data_hash did not bind interface transfer count")
	}

	differentDirection := base
	differentDirection.interfaceTransfers = append(
		[]interfaceTransferData(nil),
		base.interfaceTransfers...,
	)
	differentDirection.interfaceTransfers[0].kind = interfaceTransferSolDeposit
	if mustExternalDataHash(t, differentDirection) == baseHash {
		t.Fatal("external_data_hash did not bind interface transfer direction")
	}

	differentBump := base
	differentBump.interfaceTransfers = append(
		[]interfaceTransferData(nil),
		base.interfaceTransfers...,
	)
	differentBump.interfaceTransfers[1].splInterfaceBump++
	if mustExternalDataHash(t, differentBump) == baseHash {
		t.Fatal("external_data_hash did not bind SPL interface bump")
	}

	differentRecipient := base
	differentRecipient.interfaceTransfers = append(
		[]interfaceTransferData(nil),
		base.interfaceTransfers...,
	)
	differentRecipient.interfaceTransfers[0].userAccount[0] ^= 1
	if mustExternalDataHash(t, differentRecipient) == baseHash {
		t.Fatal("external_data_hash did not bind interface transfer recipient")
	}

	differentSplInterface := base
	differentSplInterface.interfaceTransfers = append(
		[]interfaceTransferData(nil),
		base.interfaceTransfers...,
	)
	differentSplInterface.interfaceTransfers[1].splTokenInterface[0] ^= 1
	if mustExternalDataHash(t, differentSplInterface) == baseHash {
		t.Fatal("external_data_hash did not bind SPL token interface address")
	}
}

func TestExternalDataHashBindsEncryptionContextAndOptionalHashPresence(t *testing.T) {
	base := externalDataHashInput{
		txViewingPk: [33]byte{1},
		salt:        [16]byte{2},
	}
	baseHash := mustExternalDataHash(t, base)

	differentPk := base
	differentPk.txViewingPk[0] ^= 1
	if mustExternalDataHash(t, differentPk) == baseHash {
		t.Fatal("external_data_hash did not bind tx_viewing_pk")
	}

	differentSalt := base
	differentSalt.salt[0] ^= 1
	if mustExternalDataHash(t, differentSalt) == baseHash {
		t.Fatal("external_data_hash did not bind salt")
	}

	dataHashPresent := base
	dataHashPresent.dataHashPresent = true
	if mustExternalDataHash(t, dataHashPresent) == baseHash {
		t.Fatal("external_data_hash collapsed absent data_hash and present zero data_hash")
	}

	ringDataHashPresent := base
	ringDataHashPresent.ringDataHashPresent = true
	if mustExternalDataHash(t, ringDataHashPresent) == baseHash {
		t.Fatal("external_data_hash collapsed absent ring_data_hash and present zero ring_data_hash")
	}
}

func TestBuildTransactOutputsMatchesSingleSenderBundle(t *testing.T) {
	ownerTag := [32]byte{9}
	outputs, err := buildTransactOutputs(
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
		if output.ownerTag.kind != ownerTagInline || output.ownerTag.inline != ownerTag {
			t.Fatalf("output %d owner tag = %x, want %x", i, output.ownerTag, ownerTag)
		}
	}
	if !outputs[0].dataPresent || len(outputs[0].data) != 0 {
		t.Fatal("first output must carry Some(empty) for an empty sender bundle")
	}
	if outputs[1].dataPresent {
		t.Fatal("second output must carry None")
	}

	withSomeEmpty := mustExternalDataHash(t, externalDataHashInput{outputs: outputs})
	outputs[0].dataPresent = false
	withNone := mustExternalDataHash(t, externalDataHashInput{outputs: outputs})
	if withSomeEmpty == withNone {
		t.Fatal("external_data_hash collapsed Some(empty) and None")
	}
}

func TestExternalDataPrefixRejectsUnencodableValues(t *testing.T) {
	tests := []struct {
		name    string
		data    externalDataHashInput
		wantErr string
	}{
		{"too many transfers", externalDataHashInput{interfaceTransfers: make([]interfaceTransferData, MaxInterfaceTransfers+1)}, "interface transfer count 33 exceeds protocol maximum 32"},
		{"zero transfer amount", externalDataHashInput{interfaceTransfers: []interfaceTransferData{{kind: interfaceTransferSolDeposit}}}, "interface transfer 0 amount must be nonzero"},
		{"too many outputs", externalDataHashInput{outputs: make([]transactOutputData, 256)}, "output count 256 exceeds u8"},
		{"too many messages", externalDataHashInput{messages: make([]transactMessageData, 256)}, "message count 256 exceeds u8"},
		{"long output data", externalDataHashInput{outputs: []transactOutputData{{dataPresent: true, data: make([]byte, 1<<16)}}}, "output 0 data length 65536 exceeds u16"},
		{"long message data", externalDataHashInput{messages: []transactMessageData{{data: make([]byte, 1<<16)}}}, "message 0 data length 65536 exceeds u16"},
		{"invalid transfer kind", externalDataHashInput{interfaceTransfers: []interfaceTransferData{{kind: 4, amount: 1}}}, "interface transfer 0 has invalid kind 4"},
		{"invalid owner tag", externalDataHashInput{outputs: []transactOutputData{{ownerTag: ownerTagData{kind: 2}}}}, "output 0 has invalid owner tag kind 2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := encodeExternalDataPrefix(test.data)
			if err == nil || err.Error() != test.wantErr {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
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
	realOutputs, err := buildTransactOutputs(got, ownerTag, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	withPadding, err := buildTransactOutputs([]*big.Int{real, dummy}, ownerTag, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	realHash := mustExternalDataHash(t, externalDataHashInput{outputs: realOutputs})
	paddedHash := mustExternalDataHash(t, externalDataHashInput{outputs: withPadding})
	if realHash == paddedHash {
		t.Fatal("external_data_hash did not distinguish real outputs from circuit padding")
	}

	if _, err := instructionOutputHashes([]*big.Int{real}, 2); err == nil {
		t.Fatal("out-of-range real output count must be rejected")
	}
}

func TestInterfaceTransferRequestJSONSupportsWireIntegers(t *testing.T) {
	var transfer InterfaceTransferRequest
	if err := json.Unmarshal([]byte(`{"is_spl":true,"is_deposit":true,"amount":18446744073709551615,"spl_interface_bump":255}`), &transfer); err != nil {
		t.Fatal(err)
	}
	if !transfer.IsSpl || !transfer.IsDeposit || transfer.Amount != math.MaxUint64 || transfer.SplInterfaceBump != math.MaxUint8 {
		t.Fatalf("decoded interface transfer = %+v", transfer)
	}
	if err := json.Unmarshal([]byte(`{"amount":-1}`), &transfer); err == nil {
		t.Fatal("negative interface-transfer magnitude must be rejected")
	}
	if err := json.Unmarshal([]byte(`{"spl_interface_bump":256}`), &transfer); err == nil {
		t.Fatal("SPL interface bump above u8 must be rejected")
	}
}

func TestSameAssetTransfersRemainSeparateInHashAndBundleOutput(t *testing.T) {
	requests := []InterfaceTransferRequest{
		{
			IsSpl:            true,
			IsDeposit:        true,
			Asset:            testMintA,
			Amount:           8,
			SplInterfaceBump: 11,
			UserAccount:      strings.Repeat("41", 32),
			PoolAccount:      strings.Repeat("61", 32),
		},
		{
			IsSpl:            true,
			Asset:            testMintA,
			Amount:           3,
			SplInterfaceBump: 12,
			UserAccount:      strings.Repeat("42", 32),
			PoolAccount:      strings.Repeat("62", 32),
		},
	}
	normalized, err := normalizedInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 2 ||
		normalized[0].UserAccount == normalized[1].UserAccount ||
		normalized[0].PoolAccount == normalized[1].PoolAccount ||
		normalized[0].SplInterfaceBump != requests[0].SplInterfaceBump ||
		normalized[1].SplInterfaceBump != requests[1].SplInterfaceBump {
		t.Fatalf("normalized interface transfers lost settlement identity: %+v", normalized)
	}

	built, err := buildInterfaceTransfers(requests)
	if err != nil {
		t.Fatal(err)
	}
	separateHash := mustExternalDataHash(t, externalDataHashInput{interfaceTransfers: built})
	aggregatedHash := mustExternalDataHash(t, externalDataHashInput{
		interfaceTransfers: []interfaceTransferData{{
			kind:              interfaceTransferSplDeposit,
			amount:            5,
			splInterfaceBump:  built[0].splInterfaceBump,
			userAccount:       built[0].userAccount,
			splTokenInterface: built[0].splTokenInterface,
		}},
	})
	if separateHash == aggregatedHash {
		t.Fatal("external_data_hash collapsed separate same-asset interface transfers")
	}
}

func mustExternalDataHash(t *testing.T, data externalDataHashInput) [32]byte {
	t.Helper()
	digest, err := externalDataHash(data)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func repeated16(value byte) (out [16]byte) {
	for i := range out {
		out[i] = value
	}
	return out
}

func repeated32(value byte) (out [32]byte) {
	for i := range out {
		out[i] = value
	}
	return out
}

func repeated33(value byte) (out [33]byte) {
	for i := range out {
		out[i] = value
	}
	return out
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
