package merge

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
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
	if len(got.Inputs) != len(p.Inputs) {
		t.Fatalf("input count mismatch: got %d want %d", len(got.Inputs), len(p.Inputs))
	}
	if got.MergeViewTag.Cmp(p.MergeViewTag) != 0 {
		t.Fatalf("merge view tag mismatch: got %s want %s", got.MergeViewTag, p.MergeViewTag)
	}
}

func TestMergeParametersCreateCompleteWitness(t *testing.T) {
	params := sampleParams()
	for _, circuitType := range []common.CircuitType{
		common.MergeCircuitType,
		common.MergeZoneCircuitType,
	} {
		t.Run(string(circuitType), func(t *testing.T) {
			params.CircuitType = circuitType
			assignment, err := params.CreateWitness()
			if err != nil {
				t.Fatalf("create assignment: %v", err)
			}
			if _, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("create gnark witness: %v", err)
			}
		})
	}
}

func sampleParams() *MergeParameters {
	inputs := make([]InputParams, MergeNInputs)
	for i := range inputs {
		inputs[i] = InputParams{
			Domain:                   big.NewInt(3),
			Amount:                   big.NewInt(5),
			Blinding:                 big.NewInt(7),
			ZoneDataHash:             big.NewInt(0),
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
	return &MergeParameters{
		Inputs:              inputs,
		Output:              OutputParams{ZoneDataHash: big.NewInt(0), Hash: big.NewInt(0x9999)},
		Asset:               big.NewInt(1),
		OwnerPkHash:         big.NewInt(0x1212),
		UserNullifierPk:     big.NewInt(0x3333),
		UserNullifierSecret: big.NewInt(0x4444),
		MergeViewTag:        big.NewInt(0x5555),
		OutputZoneDataHash:  big.NewInt(0),
		ExternalDataHash:    big.NewInt(0x6666),
		PrivateTxHash:       big.NewInt(0x7777),
		AllowDummyInputs:    big.NewInt(1),
		PublicInputHash:     big.NewInt(0x8888),
		ZoneProgramID:       big.NewInt(0),
	}
}

func zeros(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}
