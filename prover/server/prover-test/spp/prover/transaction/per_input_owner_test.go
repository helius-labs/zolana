package transaction

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
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

// mustNewSolanaCircuit builds the Solana-only circuit and panics on error.
func mustNewSolanaCircuit(shape txcircuit.Shape) *customzone.CustomZoneEddsaOnlyCircuit {
	circuit, err := customzone.NewCustomZoneEddsaOnlyCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func solveAssignment(t *testing.T, shape protocol.Shape, built proofAssignment) {
	t.Helper()
	circuit := mustNewSolanaCircuit(txcircuit.Shape(shape))
	if err := test.IsSolved(circuit, built.witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("assignment must solve the circuit: %v", err)
	}
}

// Spec UTXO Ownership: Ed25519 owners may differ per input. The owner tags stay
// private while the public signer transcript contains each non-payer owner.
func TestBuildProofAssignmentAcceptsDistinctSolanaOwners(t *testing.T) {
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

	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		t.Fatalf("distinct Solana owners must build: %v", err)
	}
	entries := built.publicInputs.SignerPkHashes
	if entries[0].Sign() == 0 {
		t.Fatalf("payer signer entry must be non-zero, got %v", entries[0])
	}
	if entries[1].Sign() == 0 {
		t.Fatalf("non-payer signer entry must be non-zero, got %v", entries[1])
	}
	if entries[2].Sign() != 0 {
		t.Fatalf("unused signer entry must be zero, got %v", entries[2])
	}
	if built.transcript.solanaOwnerPubkeys[0] == built.transcript.solanaOwnerPubkeys[1] {
		t.Fatal("transcript owner pubkeys must differ")
	}
	solveAssignment(t, shape, built)
}

// The P256 ownership rail is removed: a request carrying a P256-owned input
// must fail to build.
func TestBuildProofAssignmentRejectsP256Owner(t *testing.T) {
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

	if _, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{}); err == nil {
		t.Fatal("a P256-owned input must be rejected: the rail is removed")
	}
}
