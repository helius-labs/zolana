package transaction

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type fieldDerivationVector struct {
	ExternalDataHash externalDataHashVector `json:"external_data_hash"`
	SolanaPkField    solanaPkFieldVector    `json:"solana_pk_hash"`
	P256OwnerPkHash  p256OwnerPkHashVector  `json:"p256_owner_pk_hash"`
	NegativeU64      []u64FieldVector       `json:"negative_u64"`
	PublicSlots      []publicSlotsVector    `json:"public_slots"`
}

type externalDataHashVector struct {
	InstructionDiscriminator uint8                     `json:"instruction_discriminator"`
	SenderViewTag            string                    `json:"sender_view_tag"`
	TxViewingPk              string                    `json:"tx_viewing_pk"`
	Salt                     string                    `json:"salt"`
	ExpiryUnixTs             uint64                    `json:"expiry_unix_ts"`
	InterfaceTransfers       []interfaceTransferVector `json:"interface_transfers"`
	DataHash                 string                    `json:"data_hash"`
	RingDataHash             string                    `json:"ring_data_hash"`
	OutputHashes             []string                  `json:"output_hashes"`
	EncryptedUtxos           string                    `json:"encrypted_utxos"`
	Hash                     string                    `json:"hash"`
}

type interfaceTransferVector struct {
	IsSpl            bool   `json:"is_spl"`
	IsDeposit        bool   `json:"is_deposit"`
	Asset            string `json:"asset"`
	Amount           uint64 `json:"amount"`
	SplInterfaceBump uint8  `json:"spl_interface_bump"`
	UserAccount      string `json:"user_account"`
}

type solanaPkFieldVector struct {
	Pubkey string `json:"pubkey"`
	Hash   string `json:"hash"`
}

type p256OwnerPkHashVector struct {
	CompressedPubkey string `json:"compressed_pubkey"`
	Hash             string `json:"hash"`
}

type u64FieldVector struct {
	Amount uint64 `json:"amount"`
	Field  string `json:"field"`
}

type publicSlotsVector struct {
	Name               string                    `json:"name"`
	InterfaceTransfers []interfaceTransferVector `json:"interface_transfers"`
	SlotAmounts        []string                  `json:"slot_amounts"`
}

func TestFieldDerivationsKnownAnswerVector(t *testing.T) {
	vector := readFieldDerivationVector(t)

	external := vector.ExternalDataHash
	senderViewTag := mustHex32(t, external.SenderViewTag)
	outputs, err := resolveOutputs(
		vectorFieldValues(t, external.OutputHashes),
		senderViewTag,
		mustHexBytes(t, external.EncryptedUtxos),
	)
	if err != nil {
		t.Fatalf("resolve external outputs: %v", err)
	}
	interfaceTransfers, err := resolveInterfaceTransfers(vectorInterfaceTransferRequests(external.InterfaceTransfers))
	if err != nil {
		t.Fatalf("resolve external interface transfers: %v", err)
	}
	gotExternal := externalDataFieldHash(externalDataPreimage{
		InstructionDiscriminator: external.InstructionDiscriminator,
		ExpiryUnixTs:             external.ExpiryUnixTs,
		TxViewingPk:              mustHex33(t, external.TxViewingPk),
		Salt:                     mustHex16(t, external.Salt),
		InterfaceTransfers:       interfaceTransfers,
		DataHashPresent:          false,
		DataHash:                 mustFieldBytes(t, external.DataHash),
		RingDataHashPresent:      false,
		RingDataHash:             mustFieldBytes(t, external.RingDataHash),
		Outputs:                  outputs,
	})
	expectField(t, "external_data_hash", gotExternal, external.Hash)

	solanaHash, err := protocol.SolanaPkField(mustHex32(t, vector.SolanaPkField.Pubkey))
	if err != nil {
		t.Fatalf("solana pk hash: %v", err)
	}
	expectField(t, "solana_pk_hash", solanaHash, vector.SolanaPkField.Hash)

	p256OwnerHash, err := protocol.OwnerPkField(mustHexBytes(t, vector.P256OwnerPkHash.CompressedPubkey))
	if err != nil {
		t.Fatalf("p256 owner pk hash: %v", err)
	}
	expectField(t, "p256_owner_pk_hash", p256OwnerHash, vector.P256OwnerPkHash.Hash)

	for _, item := range vector.NegativeU64 {
		value := new(big.Int).SetUint64(item.Amount)
		got := protocol.SignedToField(value.Neg(value))
		expectField(t, "negative_u64 "+new(big.Int).SetUint64(item.Amount).String(), got, item.Field)
	}

	for _, item := range vector.PublicSlots {
		slots, err := derivePublicSlots(ProofTransactionRequest{
			InterfaceTransfers: vectorInterfaceTransferRequests(item.InterfaceTransfers),
		})
		if err != nil {
			t.Fatalf("public slots %s: %v", item.Name, err)
		}
		if len(item.SlotAmounts) != protocol.NPublicSlots {
			t.Fatalf("public slots %s: got %d expected amounts, want %d", item.Name, len(item.SlotAmounts), protocol.NPublicSlots)
		}
		if !slices.EqualFunc(
			slots.amounts[:],
			item.SlotAmounts,
			func(got *big.Int, want string) bool {
				return got.Cmp(mustField(t, want)) == 0
			},
		) {
			t.Errorf("public_slots.%s amounts mismatch: got %v, want %v", item.Name, slots.amounts, item.SlotAmounts)
		}
	}
}

func vectorFieldValues(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, 0, len(values))
	for _, value := range values {
		out = append(out, mustField(t, value))
	}
	return out
}

func vectorInterfaceTransferRequests(transfers []interfaceTransferVector) []InterfaceTransferRequest {
	out := make([]InterfaceTransferRequest, 0, len(transfers))
	for _, transfer := range transfers {
		out = append(out, InterfaceTransferRequest{
			IsSpl:            transfer.IsSpl,
			IsDeposit:        transfer.IsDeposit,
			Asset:            transfer.Asset,
			Amount:           transfer.Amount,
			SplInterfaceBump: transfer.SplInterfaceBump,
			UserAccount:      transfer.UserAccount,
		})
	}
	return out
}

func readFieldDerivationVector(t *testing.T) fieldDerivationVector {
	t.Helper()
	bytes, err := os.ReadFile("../../testdata/field_derivation_vector.json")
	if err != nil {
		t.Fatalf("read field derivation vector: %v", err)
	}
	var vector fieldDerivationVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatalf("decode field derivation vector: %v", err)
	}
	return vector
}

func expectField(t *testing.T, name string, got *big.Int, wantHex string) {
	t.Helper()
	want := mustField(t, wantHex)
	if got.Cmp(want) != 0 {
		t.Errorf("%s mismatch:\ngot  0x%s\nwant 0x%s", name, parse.FieldHex(got), parse.FieldHex(want))
	}
}

func mustField(t *testing.T, value string) *big.Int {
	t.Helper()
	out, err := parse.Field(value)
	if err != nil {
		t.Fatalf("parse field %q: %v", value, err)
	}
	return out
}

func mustHex32(t *testing.T, value string) [32]byte {
	t.Helper()
	out, err := parse.Hex32(value)
	if err != nil {
		t.Fatalf("parse hex32 %q: %v", value, err)
	}
	return out
}

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	out, err := parse.HexBytes(value)
	if err != nil {
		t.Fatalf("parse hex bytes %q: %v", value, err)
	}
	return out
}

func mustHex33(t *testing.T, value string) [33]byte {
	t.Helper()
	bytes := mustHexBytes(t, value)
	if len(bytes) != 33 {
		t.Fatalf("parse hex33 %q: expected 33 bytes, got %d", value, len(bytes))
	}
	var out [33]byte
	copy(out[:], bytes)
	return out
}

func mustHex16(t *testing.T, value string) [16]byte {
	t.Helper()
	bytes := mustHexBytes(t, value)
	if len(bytes) != 16 {
		t.Fatalf("parse hex16 %q: expected 16 bytes, got %d", value, len(bytes))
	}
	var out [16]byte
	copy(out[:], bytes)
	return out
}

func mustFieldBytes(t *testing.T, value string) [32]byte {
	t.Helper()
	out, err := parse.FieldBytes(mustField(t, value))
	if err != nil {
		t.Fatalf("encode field %q: %v", value, err)
	}
	return out
}
