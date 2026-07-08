package squadszone

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestZoneParametersJSONRoundTripWithDummyFlags(t *testing.T) {
	p := sampleZoneParams(2, 2)
	p.InputsDummy = []*big.Int{big.NewInt(1)}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), "inputsDummy") {
		t.Fatalf("expected inputsDummy in JSON: %s", data)
	}

	var got ZoneParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.ValidateShape(); err != nil {
		t.Fatalf("validate shape after round trip: %v", err)
	}
	if len(got.InputsDummy) != 1 {
		t.Fatalf("dummy flag count: got %d want 1", len(got.InputsDummy))
	}
	if got.InputsDummy[0].Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("dummy flag mismatch: got %s want 1", got.InputsDummy[0])
	}
	if got.PublicInputHash.Cmp(p.PublicInputHash) != 0 {
		t.Fatalf("public input hash mismatch")
	}
}

func TestZoneParametersJSONAbsentDummyFlagsDefaultToZeros(t *testing.T) {
	p := sampleZoneParams(2, 2)

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "inputsDummy") {
		t.Fatalf("expected inputsDummy omitted: %s", data)
	}

	var got ZoneParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.InputsDummy) != 1 {
		t.Fatalf("dummy flag count: got %d want 1", len(got.InputsDummy))
	}
	if got.InputsDummy[0].Sign() != 0 {
		t.Fatalf("dummy flag should default to 0, got %s", got.InputsDummy[0])
	}
}

func TestZoneParametersJSONRejectsWrongDummyFlagCount(t *testing.T) {
	p := sampleZoneParams(2, 2)
	p.InputsDummy = []*big.Int{big.NewInt(0), big.NewInt(1)}

	if err := p.ValidateShape(); err == nil {
		t.Fatal("expected shape validation failure for wrong dummy flag count")
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ZoneParameters
	if err := json.Unmarshal(data, &got); err == nil {
		t.Fatal("expected unmarshal failure for wrong inputsDummy length")
	}
}

func TestZoneParametersJSONSingleInputHasNoDummyFlags(t *testing.T) {
	p := sampleZoneParams(1, 1)

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ZoneParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.InputsDummy) != 0 {
		t.Fatalf("dummy flag count: got %d want 0", len(got.InputsDummy))
	}
}

func sampleZoneParams(nInputs, nOutputs uint32) *ZoneParameters {
	utxo := UtxoParams{
		OwnerHash: big.NewInt(2), Asset: big.NewInt(1), Amount: big.NewInt(5),
		Blinding: big.NewInt(7), ProgramDataHash: big.NewInt(0),
		ZoneDataHash: big.NewInt(0), ZoneProgramID: big.NewInt(0),
	}
	inputs := make([]UtxoParams, nInputs)
	outputs := make([]UtxoParams, nOutputs)
	for i := range inputs {
		inputs[i] = utxo
	}
	for i := range outputs {
		outputs[i] = utxo
	}
	viewing := [65]*big.Int{}
	for i := range viewing {
		viewing[i] = big.NewInt(int64(i))
	}
	return &ZoneParameters{
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		Inputs:           inputs,
		Outputs:          outputs,
		ExternalDataHash: big.NewInt(0x1111),
		Sender: SenderParams{
			Owner:                            big.NewInt(0x2222),
			SharedViewingSecretKeyCommitment: big.NewInt(0x3333),
			NullifierPubkey:                  big.NewInt(0x4444),
			NullifierSecret:                  big.NewInt(0x5555),
			SharedViewingSecretKey:           big.NewInt(0x6666),
		},
		Recipient: RecipientParams{
			Owner:           big.NewInt(0x7777),
			NullifierPubkey: big.NewInt(0x8888),
			ViewingPubkey:   viewing,
		},
		Proposal: ProposalParams{
			Amount:       big.NewInt(0),
			Recipient:    big.NewInt(0),
			Blinding:     big.NewInt(0),
			PublicAmount: big.NewInt(0),
		},
		EnableProposalHash: big.NewInt(0),
		PublicAmount:       big.NewInt(0),
		PublicInputHash:    big.NewInt(0x9999),
	}
}
