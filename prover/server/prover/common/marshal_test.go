package common

import (
	"encoding/json"
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func TestCommittedProofJSONRoundTrip(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	var commitment, commitmentPok bn254.G1Affine
	commitment.ScalarMultiplication(&g1, big.NewInt(2))
	commitmentPok.ScalarMultiplication(&g1, big.NewInt(3))

	original := &Proof{Proof: &groth16bn254.Proof{
		Ar:            g1,
		Bs:            g2,
		Krs:           g1,
		Commitments:   []bn254.G1Affine{commitment},
		CommitmentPok: commitmentPok,
	}}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal committed proof: %v", err)
	}

	var decoded Proof
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal committed proof: %v", err)
	}

	decodedProof, ok := decoded.Proof.(*groth16bn254.Proof)
	if !ok {
		t.Fatalf("decoded proof type = %T, want *groth16bn254.Proof", decoded.Proof)
	}
	if len(decodedProof.Commitments) != 1 {
		t.Fatalf("decoded commitment count = %d, want 1", len(decodedProof.Commitments))
	}
	if !decodedProof.Commitments[0].Equal(&commitment) {
		t.Fatal("decoded proof commitment does not match")
	}
	if !decodedProof.CommitmentPok.Equal(&commitmentPok) {
		t.Fatal("decoded proof commitment PoK does not match")
	}
}
