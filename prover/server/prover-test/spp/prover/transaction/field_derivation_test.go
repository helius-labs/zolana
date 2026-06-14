package transaction

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type fieldDerivationVector struct {
	ExternalDataHash     externalDataHashVector `json:"external_data_hash"`
	SolanaPkField        solanaPkFieldVector    `json:"solana_pk_hash"`
	P256MessageHash      p256MessageHashVector  `json:"p256_message_hash"`
	NegativeU64          []u64FieldVector       `json:"negative_u64"`
	PublicAmounts        []publicAmountVector   `json:"public_amounts"`
	PublicSplAssetPubkey string                 `json:"public_spl_asset_pubkey"`
}

type externalDataHashVector struct {
	InstructionDiscriminator uint8  `json:"instruction_discriminator"`
	SenderViewTag            string `json:"sender_view_tag"`
	RelayerFee               uint16 `json:"relayer_fee"`
	ExpiryUnixTs             uint64 `json:"expiry_unix_ts"`
	PublicSolAmount          uint64 `json:"public_sol_amount"`
	PublicSplAmount          uint64 `json:"public_spl_amount"`
	UserSolAccount           string `json:"user_sol_account"`
	UserSplTokenAccount      string `json:"user_spl_token_account"`
	SplTokenInterface        string `json:"spl_token_interface"`
	EncryptedUtxos           string `json:"encrypted_utxos"`
	Hash                     string `json:"hash"`
}

type solanaPkFieldVector struct {
	Pubkey string `json:"pubkey"`
	Hash   string `json:"hash"`
}

type p256MessageHashVector struct {
	PrivateTxHash string `json:"private_tx_hash"`
	Hash          string `json:"hash"`
}

type u64FieldVector struct {
	Amount uint64 `json:"amount"`
	Field  string `json:"field"`
}

type publicAmountVector struct {
	Name            string `json:"name"`
	Mode            uint8  `json:"mode"`
	RelayerFee      uint16 `json:"relayer_fee"`
	PublicSolAmount uint64 `json:"public_sol_amount"`
	PublicSplAmount uint64 `json:"public_spl_amount"`
	Sol             string `json:"sol"`
	Spl             string `json:"spl"`
}

func TestFieldDerivationsKnownAnswerVector(t *testing.T) {
	vector := readFieldDerivationVector(t)

	external := vector.ExternalDataHash
	gotExternal := externalDataFieldHash(externalDataPreimage{
		InstructionDiscriminator: external.InstructionDiscriminator,
		SenderViewTag:            mustHex32(t, external.SenderViewTag),
		RelayerFee:               external.RelayerFee,
		ExpiryUnixTs:             external.ExpiryUnixTs,
		PublicSolAmount:          external.PublicSolAmount,
		PublicSplAmount:          external.PublicSplAmount,
		UserSolAccount:           mustHex32(t, external.UserSolAccount),
		UserSplToken:             mustHex32(t, external.UserSplTokenAccount),
		SplTokenInterface:        mustHex32(t, external.SplTokenInterface),
		EncryptedUtxos:           mustHexBytes(t, external.EncryptedUtxos),
	})
	expectField(t, "external_data_hash", gotExternal, external.Hash)

	solanaHash, err := protocol.SolanaPkField(mustHex32(t, vector.SolanaPkField.Pubkey))
	if err != nil {
		t.Fatalf("solana pk hash: %v", err)
	}
	expectField(t, "solana_pk_hash", solanaHash, vector.SolanaPkField.Hash)

	p256Digest, err := protocol.P256MessageDigest(mustField(t, vector.P256MessageHash.PrivateTxHash))
	if err != nil {
		t.Fatalf("p256 message digest: %v", err)
	}
	p256MessageLow, p256MessageHigh := protocol.P256MessageLimbs(p256Digest)
	p256MessageHash, err := protocol.P256MessageHashField(p256MessageLow, p256MessageHigh)
	if err != nil {
		t.Fatalf("p256 message hash field: %v", err)
	}
	expectField(t, "p256_message_hash", p256MessageHash, vector.P256MessageHash.Hash)

	for _, item := range vector.NegativeU64 {
		value := new(big.Int).SetUint64(item.Amount)
		got := protocol.SignedToField(value.Neg(value))
		expectField(t, "negative_u64 "+new(big.Int).SetUint64(item.Amount).String(), got, item.Field)
	}

	for _, item := range vector.PublicAmounts {
		amounts, err := derivePublicAmounts(ProofTransactionRequest{
			PublicAmountMode:     item.Mode,
			RelayerFee:           item.RelayerFee,
			PublicSolAmount:      &item.PublicSolAmount,
			PublicSplAmount:      &item.PublicSplAmount,
			PublicSplAssetPubkey: vector.PublicSplAssetPubkey,
		})
		if err != nil {
			t.Fatalf("public amount %s: %v", item.Name, err)
		}
		expectField(t, "public_amounts."+item.Name+".sol", amounts.sol, item.Sol)
		expectField(t, "public_amounts."+item.Name+".spl", amounts.spl, item.Spl)
	}
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
