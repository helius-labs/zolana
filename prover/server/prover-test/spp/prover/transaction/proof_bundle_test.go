package transaction

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
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

type sharedExternalDataVector struct {
	InstructionDiscriminator uint8  `json:"instructionDiscriminator"`
	ExpiryUnixTs             uint64 `json:"expiryUnixTs"`
	TxViewingPk              string `json:"txViewingPk"`
	Salt                     string `json:"salt"`
	InterfaceTransfers       []struct {
		Kind                string `json:"kind"`
		Amount              uint64 `json:"amount"`
		SplInterfaceBump    uint8  `json:"splInterfaceBump"`
		UserAccount         string `json:"userAccount"`
		SplInterfaceAccount string `json:"splInterfaceAccount"`
	} `json:"interfaceTransfers"`
	DataHash     *string `json:"dataHash"`
	RingDataHash *string `json:"ringDataHash"`
	Outputs      []struct {
		UtxoHash string `json:"utxoHash"`
		OwnerTag struct {
			Kind    string `json:"kind"`
			Value   string `json:"value"`
			Index   uint8  `json:"index"`
			Address string `json:"address"`
		} `json:"ownerTag"`
		Data *string `json:"data"`
	} `json:"outputs"`
	Messages []struct {
		ViewTag string `json:"viewTag"`
		Data    string `json:"data"`
	} `json:"messages"`
	CommittedAddresses []string `json:"committedAddresses"`
	ExternalDataPrefix string   `json:"externalDataPrefix"`
	ExternalDataHash   string   `json:"externalDataHash"`
}

func loadSharedExternalDataVector(t *testing.T) sharedExternalDataVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate proof_bundle_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../../test-vectors/external_data_hash.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector sharedExternalDataVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func vectorBytes(t *testing.T, label, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return decoded
}

func vectorFixed(t *testing.T, label, value string, dst []byte) {
	t.Helper()
	decoded := vectorBytes(t, label, value)
	if len(decoded) != len(dst) {
		t.Fatalf("%s: expected %d bytes, got %d", label, len(dst), len(decoded))
	}
	copy(dst, decoded)
}

func vector32(t *testing.T, label, value string) (out [32]byte) {
	t.Helper()
	vectorFixed(t, label, value, out[:])
	return out
}

func interfaceTransferKindFromVector(t *testing.T, label, name string) interfaceTransferKind {
	t.Helper()
	switch name {
	case "solDeposit":
		return interfaceTransferSolDeposit
	case "solWithdrawal":
		return interfaceTransferSolWithdrawal
	case "splDeposit":
		return interfaceTransferSplDeposit
	case "splWithdrawal":
		return interfaceTransferSplWithdrawal
	default:
		t.Fatalf("%s: unknown interface transfer kind %q", label, name)
		return 0
	}
}

func externalDataHashInputFromSharedVector(t *testing.T, vector sharedExternalDataVector) externalDataHashInput {
	t.Helper()
	data := externalDataHashInput{
		instructionDiscriminator: vector.InstructionDiscriminator,
		expiryUnixTs:             vector.ExpiryUnixTs,
	}
	vectorFixed(t, "txViewingPk", vector.TxViewingPk, data.txViewingPk[:])
	vectorFixed(t, "salt", vector.Salt, data.salt[:])
	for i, transfer := range vector.InterfaceTransfers {
		label := fmt.Sprintf("interfaceTransfers[%d]", i)
		built := interfaceTransferData{
			kind:             interfaceTransferKindFromVector(t, label, transfer.Kind),
			amount:           transfer.Amount,
			splInterfaceBump: transfer.SplInterfaceBump,
			userAccount:      vector32(t, label+".userAccount", transfer.UserAccount),
		}
		if transfer.SplInterfaceAccount != "" {
			built.splTokenInterface = vector32(t, label+".splInterfaceAccount", transfer.SplInterfaceAccount)
		}
		data.interfaceTransfers = append(data.interfaceTransfers, built)
	}
	if vector.DataHash != nil {
		data.dataHashPresent = true
		data.dataHash = vector32(t, "dataHash", *vector.DataHash)
	}
	if vector.RingDataHash != nil {
		data.ringDataHashPresent = true
		data.ringDataHash = vector32(t, "ringDataHash", *vector.RingDataHash)
	}
	for i, output := range vector.Outputs {
		label := fmt.Sprintf("outputs[%d]", i)
		built := transactOutputData{utxoHash: vector32(t, label+".utxoHash", output.UtxoHash)}
		switch output.OwnerTag.Kind {
		case "inline":
			built.ownerTag = ownerTagData{
				kind:   ownerTagInline,
				inline: vector32(t, label+".ownerTag.value", output.OwnerTag.Value),
			}
		case "account":
			built.ownerTag = ownerTagData{
				kind:           ownerTagAccount,
				accountIndex:   output.OwnerTag.Index,
				accountAddress: vector32(t, label+".ownerTag.address", output.OwnerTag.Address),
			}
		default:
			t.Fatalf("%s: unknown owner tag kind %q", label, output.OwnerTag.Kind)
		}
		if output.Data != nil {
			built.dataPresent = true
			built.data = vectorBytes(t, label+".data", *output.Data)
		}
		data.outputs = append(data.outputs, built)
	}
	for i, message := range vector.Messages {
		label := fmt.Sprintf("messages[%d]", i)
		data.messages = append(data.messages, transactMessageData{
			viewTag: vector32(t, label+".viewTag", message.ViewTag),
			data:    vectorBytes(t, label+".data", message.Data),
		})
	}
	return data
}

func TestExternalDataHashMatchesSharedVector(t *testing.T) {
	vector := loadSharedExternalDataVector(t)
	data := externalDataHashInputFromSharedVector(t, vector)

	var committed []string
	for _, transfer := range data.interfaceTransfers {
		committed = append(committed, fmt.Sprintf("%x", transfer.userAccount))
		if transfer.kind == interfaceTransferSplDeposit || transfer.kind == interfaceTransferSplWithdrawal {
			committed = append(committed, fmt.Sprintf("%x", transfer.splTokenInterface))
		}
	}
	for _, output := range data.outputs {
		if output.ownerTag.kind == ownerTagAccount {
			committed = append(committed, fmt.Sprintf("%x", output.ownerTag.accountAddress))
		}
	}
	if strings.Join(committed, ",") != strings.Join(vector.CommittedAddresses, ",") {
		t.Fatalf("committed addresses = %v, vector lists %v", committed, vector.CommittedAddresses)
	}

	prefix, err := encodeExternalDataPrefix(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", prefix); got != vector.ExternalDataPrefix {
		t.Fatalf("external-data prefix mismatch:\ngot  %s\nwant %s", got, vector.ExternalDataPrefix)
	}

	wantHash := vector32(t, "externalDataHash", vector.ExternalDataHash)
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

func TestInterfaceTransferRequestJSONSupportsFullRangeIntegers(t *testing.T) {
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
