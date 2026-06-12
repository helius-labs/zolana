package transaction

import (
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

// refreshStateEntry recomputes the state-tree leaf for an input whose owner
// was mutated, so the witness builder reaches the owner checks instead of
// failing the leaf lookup.
func refreshStateEntry(t *testing.T, tx *ProofTransactionRequest, i int) {
	t.Helper()
	parsed, err := parseProofInput(tx.Inputs[i])
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocol.UtxoHash(parsed.utxo)
	if err != nil {
		t.Fatal(err)
	}
	tx.StateEntries[i].Hash = proofFieldInput(hash)
}

func TestBuildProofAssignmentRejectsDifferingSolanaOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	var otherOwner [32]byte
	for i := range otherOwner {
		otherOwner[i] = byte(i + 101)
	}
	tx.Inputs[1].Utxo.OwnerSolanaPubkey = parse.BytesHex(otherOwner[:])
	refreshStateEntry(t, &tx, 1)

	_, err = buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "input 1 Solana owner differs from earlier inputs") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildProofAssignmentRejectsMixedP256AndSolanaOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().ScalarBaseMult(big.NewInt(11).Bytes())
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	tx.Inputs[0].Utxo.OwnerSolanaPubkey = ""
	tx.Inputs[0].Utxo.OwnerP256Pubkey = parse.BytesHex(compressed)
	refreshStateEntry(t, &tx, 0)

	_, err = buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "transaction mixes P256-owned and Solana-owned inputs") {
		t.Fatalf("error = %v", err)
	}
}
