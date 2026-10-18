package common

import (
	"encoding/json"
	"math/big"
	"strings"
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

// A malformed witness value must not come back in the error: a prover
// relays FromHex failures to its caller.
func TestFromHexDoesNotEchoTheInput(t *testing.T) {
	var value big.Int
	err := FromHex(&value, "review-private-sentinel")
	if err == nil || err.Error() != "invalid number" {
		t.Fatalf("got %v", err)
	}
}

func TestProofJSONRejectsCoordinateAliases(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	proof := &Proof{Proof: &groth16bn254.Proof{Ar: g1, Bs: g2, Krs: g1}}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var original ProofJSON
	if err := json.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProofJSON)
	}{
		{"overwide", func(w *ProofJSON) { w.Ar[0] = "0x1" + strings.Repeat("0", 64) }},
		{"negative", func(w *ProofJSON) { w.Bs[0][0] = "-1" }},
		{"short", func(w *ProofJSON) { w.Krs[0] = "0x01" }},
		{"uppercase", func(w *ProofJSON) { w.Ar[1] = strings.ToUpper(w.Ar[1]) }},
		{"missing_prefix", func(w *ProofJSON) { w.Bs[1][1] = strings.TrimPrefix(w.Bs[1][1], "0x") }},
		{"overwide_commitment", func(w *ProofJSON) {
			w.ProofCommitment = []string{"0x1" + strings.Repeat("0", 64), "0x00"}
			w.ProofCommitmentPok = []string{"0x00", "0x00"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := original
			test.mutate(&wire)
			payload, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Proof
			if err := json.Unmarshal(payload, &decoded); err == nil || !strings.Contains(err.Error(), "invalid proof coordinate") {
				t.Fatalf("malformed proof coordinate accepted: %v", err)
			}
		})
	}
}
