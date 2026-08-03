package transfereddsaonly

import (
	"encoding/json"
	"math/big"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

func TestP256TransferParametersJSONRoundTrip(t *testing.T) {
	zero := big.NewInt(0)
	utxo := UtxoParams{
		Domain:        zero,
		Owner:         zero,
		Asset:         zero,
		Amount:        zero,
		Blinding:      zero,
		DataHash:      zero,
		RingDataHash:  zero,
		RingProgramID: zero,
	}
	params := P256TransferParameters{
		NInputs:  1,
		NOutputs: 1,
		Inputs: []InputParams{{
			Utxo:                     utxo,
			IsDummy:                  zero,
			StatePathElements:        make([]*big.Int, txcircuit.StateTreeHeight),
			StatePathIndex:           zero,
			NullifierLowValue:        zero,
			NullifierNextValue:       zero,
			NullifierLowPathElements: make([]*big.Int, txcircuit.NullifierTreeHeight),
			NullifierLowPathIndex:    zero,
			UtxoTreeRoot:             zero,
			NullifierTreeRoot:        zero,
			Nullifier:                zero,
			OwnerPkHash:              zero,
			NullifierSecret:          zero,
		}},
		Outputs: []OutputParams{{
			Utxo:        utxo,
			IsDummy:     zero,
			Hash:        zero,
			OwnerPkHash: zero,
			NullifierPk: zero,
		}},
		ExternalDataHash:    zero,
		PrivateTxHash:       zero,
		P256PubX:            zero,
		P256PubY:            zero,
		P256SigR:            zero,
		P256SigS:            zero,
		P256MessageHashLow:  zero,
		P256MessageHashHigh: zero,
		PublicAssets:        []*big.Int{zero, zero, zero},
		PublicAmounts:       []*big.Int{zero, zero, zero},
		RingProgramID:       zero,
		SignerPkHashes:      []*big.Int{zero, zero},
		AllowDummyInputs:    zero,
		PublicInputHash:     zero,
	}
	for i := range params.Inputs[0].StatePathElements {
		params.Inputs[0].StatePathElements[i] = zero
	}
	for i := range params.Inputs[0].NullifierLowPathElements {
		params.Inputs[0].NullifierLowPathElements[i] = zero
	}

	encoded, err := json.Marshal(&params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw["circuitType"] != string(common.TransferP256RingCircuitType) {
		t.Fatalf("circuit type = %v", raw["circuitType"])
	}
	if _, exists := raw["p256SigningPkField"]; exists {
		t.Fatal("obsolete p256SigningPkField must not be serialized")
	}

	var decoded P256TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if decoded.NInputs != 1 || decoded.NOutputs != 1 {
		t.Fatalf("shape = %dx%d", decoded.NInputs, decoded.NOutputs)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatalf("validate shape: %v", err)
	}
}
