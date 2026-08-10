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

func TestProposalContextReachesWitnessVerbatim(t *testing.T) {
	p := sampleZoneParams(1, 1)
	asset := new(big.Int).SetBytes([]byte{
		0x03, 0xdf, 0x2d, 0x93, 0xdf, 0xa1, 0xb0, 0x06,
		0xbb, 0xad, 0x4e, 0x16, 0x63, 0x8c, 0xc7, 0x92,
		0x1f, 0x64, 0x88, 0xce, 0x29, 0x5d, 0xe4, 0x67,
		0x1e, 0x79, 0xeb, 0x7f, 0x17, 0x7f, 0xbd, 0xb4,
	})
	destination := new(big.Int).SetBytes([]byte{
		0x05, 0xf8, 0xab, 0xf0, 0xc3, 0x1c, 0x1f, 0x86,
		0xe6, 0xd1, 0x24, 0x3f, 0xe8, 0x69, 0xab, 0xfc,
		0xf6, 0x06, 0x96, 0xfd, 0xe3, 0x5e, 0xdc, 0x1c,
		0x1a, 0xfd, 0x6a, 0x14, 0x3d, 0xcd, 0x2a, 0x2a,
	})
	p.Proposal.Asset = asset
	p.Proposal.Destination = destination

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ZoneParameters
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assignment, err := decoded.CreateWitness()
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}
	gotAsset, ok := assignment.Proposal.Asset.(*big.Int)
	if !ok || gotAsset.Cmp(asset) != 0 {
		t.Fatalf("proposal asset changed before witness assignment: %v", assignment.Proposal.Asset)
	}
	gotDestination, ok := assignment.Proposal.Destination.(*big.Int)
	if !ok || gotDestination.Cmp(destination) != 0 {
		t.Fatalf("proposal destination changed before witness assignment: %v", assignment.Proposal.Destination)
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
			Asset:        big.NewInt(0),
			Destination:  big.NewInt(0),
			Blinding:     big.NewInt(0),
			PublicAmount: big.NewInt(0),
		},
		EnableProposalHash: big.NewInt(0),
		PublicAmount:       big.NewInt(0),
		PublicInputHash:    big.NewInt(0x9999),
	}
}
