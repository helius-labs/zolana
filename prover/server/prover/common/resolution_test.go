package common

import (
	"encoding/json"
	"reflect"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func TestResolutionSurvivesQueuedProofEncoding(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	resolution := &ProofResolution{PublicInputHash: "0x123", Trees: []ResolvedTree{{Tree: "11111111111111111111111111111111", ID: 2, UtxoRoot: "0x1", NullifierRoot: "0x2", UtxoRootIndex: 3, NullifierRootIndex: 4}}}
	original := &Proof{Proof: &groth16bn254.Proof{Ar: g1, Bs: g2, Krs: g1}, Resolution: resolution}
	envelope := struct {
		Proof *Proof `json:"proof"`
	}{Proof: original}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Proof *Proof `json:"proof"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Proof == nil || !reflect.DeepEqual(decoded.Proof.Resolution, resolution) {
		t.Fatal("queued proof lost its root binding")
	}
}
