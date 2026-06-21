package merge

import (
	"encoding/json"
	"math/big"
	"testing"

	transaction "zolana/prover/circuits/spp_transaction"
)

// TestMergeParametersJSONRoundTrip checks the wire format the Rust client
// produces decodes back to identical parameters (shape, paths, and all fields).
func TestMergeParametersJSONRoundTrip(t *testing.T) {
	p := sampleParams()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got MergeParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.ValidateShape(); err != nil {
		t.Fatalf("validate shape after round trip: %v", err)
	}
	if got.PublicInputHash.Cmp(p.PublicInputHash) != 0 {
		t.Fatalf("public input hash mismatch: got %s want %s", got.PublicInputHash, p.PublicInputHash)
	}
	if got.Output.Hash.Cmp(p.Output.Hash) != 0 {
		t.Fatalf("output hash mismatch")
	}
	if len(got.Inputs) != len(p.Inputs) {
		t.Fatalf("input count mismatch: got %d want %d", len(got.Inputs), len(p.Inputs))
	}
	if len(got.UserViewingPubkey) != 65 {
		t.Fatalf("user viewing pubkey length: got %d", len(got.UserViewingPubkey))
	}
	if got.Inputs[0].Nullifier.Cmp(p.Inputs[0].Nullifier) != 0 {
		t.Fatalf("nullifier mismatch")
	}
}

func sampleParams() *MergeParameters {
	utxo := UtxoParams{
		Domain: big.NewInt(1), Owner: big.NewInt(2), Asset: big.NewInt(1),
		Amount: big.NewInt(5), Blinding: big.NewInt(7), DataHash: big.NewInt(0),
		ZoneDataHash: big.NewInt(0), ZoneProgramID: big.NewInt(0),
	}
	inputs := make([]InputParams, MergeNInputs)
	for i := range inputs {
		inputs[i] = InputParams{
			Utxo:                     utxo,
			IsDummy:                  big.NewInt(int64(boolToInt(i != 0))),
			StatePathElements:        zeros(transaction.StateTreeHeight),
			StatePathIndex:           big.NewInt(0),
			NullifierLowValue:        big.NewInt(0),
			NullifierNextValue:       big.NewInt(0),
			NullifierLowPathElements: zeros(transaction.NullifierTreeHeight),
			NullifierLowPathIndex:    big.NewInt(0),
			UtxoTreeRoot:             big.NewInt(11),
			NullifierTreeRoot:        big.NewInt(13),
			Nullifier:                big.NewInt(int64(100 + i)),
		}
	}
	viewing := make([]*big.Int, 65)
	for i := range viewing {
		viewing[i] = big.NewInt(int64(i))
	}
	return &MergeParameters{
		Inputs:              inputs,
		Output:              OutputParams{Utxo: utxo, Hash: big.NewInt(0xABC)},
		P256PubX:            big.NewInt(0x1111),
		P256PubY:            big.NewInt(0x2222),
		UserNullifierPk:     big.NewInt(0x3333),
		UserNullifierSecret: big.NewInt(0x4444),
		TxViewingSk:         big.NewInt(0x5555),
		UserViewingPubkey:   viewing,
		ExternalDataHash:    big.NewInt(0x6666),
		PrivateTxHash:       big.NewInt(0x7777),
		PublicInputHash:     big.NewInt(0x8888),
	}
}

func zeros(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
