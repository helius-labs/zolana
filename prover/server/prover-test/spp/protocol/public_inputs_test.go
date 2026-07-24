package protocol

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"zolana/prover/prover-test/spp/parse"
)

type publicInputHashVector struct {
	Nullifiers         []string `json:"nullifiers"`
	OutputUtxoHashes   []string `json:"output_utxo_hashes"`
	UtxoTreeRoots      []string `json:"utxo_tree_roots"`
	NullifierTreeRoots []string `json:"nullifier_tree_roots"`
	PrivateTxHash      string   `json:"private_tx_hash"`
	P256MessageHash    string   `json:"p256_message_hash"`
	ExternalDataHash   string   `json:"external_data_hash"`
	PublicAssets       []string `json:"public_assets"`
	PublicAmounts      []string `json:"public_amounts"`
	ZoneProgramID      string   `json:"zone_program_id"`
	PayerPubkeyHash    string   `json:"payer_pubkey_hash"`
	InputOwnerPkHashes []string `json:"input_owner_pk_hashes"`
	PublicInputHash    string   `json:"public_input_hash"`
}

func TestPublicInputHashKnownAnswerVector(t *testing.T) {
	vector := readPublicInputHashVector(t)
	if len(vector.PublicAssets) != NPublicSlots || len(vector.PublicAmounts) != NPublicSlots {
		t.Fatalf("vector public slot count: got %d assets and %d amounts, want %d",
			len(vector.PublicAssets), len(vector.PublicAmounts), NPublicSlots)
	}
	inputs := PublicInputs{
		Nullifiers:         parseFields(t, vector.Nullifiers),
		OutputUtxoHashes:   parseFields(t, vector.OutputUtxoHashes),
		UtxoTreeRoots:      parseFields(t, vector.UtxoTreeRoots),
		NullifierTreeRoots: parseFields(t, vector.NullifierTreeRoots),
		PrivateTxHash:      parseField(t, vector.PrivateTxHash),
		P256MessageHash:    parseField(t, vector.P256MessageHash),
		ExternalDataHash:   parseField(t, vector.ExternalDataHash),
		ZoneProgramID:      parseField(t, vector.ZoneProgramID),
		PayerPubkeyHash:    parseField(t, vector.PayerPubkeyHash),
		InputOwnerPkHashes: parseFields(t, vector.InputOwnerPkHashes),
	}
	for i := 0; i < NPublicSlots; i++ {
		inputs.PublicAssets[i] = parseField(t, vector.PublicAssets[i])
		inputs.PublicAmounts[i] = parseField(t, vector.PublicAmounts[i])
	}
	got, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("public input hash: %v", err)
	}

	want := parseField(t, vector.PublicInputHash)
	if got.Cmp(want) != 0 {
		t.Fatalf("public input hash mismatch:\ngot  0x%s\nwant 0x%s", parse.FieldHex(got), parse.FieldHex(want))
	}
}

func readPublicInputHashVector(t *testing.T) publicInputHashVector {
	t.Helper()
	bytes, err := os.ReadFile("../testdata/public_input_hash_vector.json")
	if err != nil {
		t.Fatalf("read public input hash vector: %v", err)
	}
	var vector publicInputHashVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatalf("decode public input hash vector: %v", err)
	}
	return vector
}

func parseFields(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = parseField(t, value)
	}
	return out
}

func parseField(t *testing.T, value string) *big.Int {
	t.Helper()
	out, err := parse.Field(value)
	if err != nil {
		t.Fatalf("parse field %q: %v", value, err)
	}
	return out
}
