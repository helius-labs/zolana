package transaction

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction"
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

// mustNewCircuit builds the P256-capable circuit and panics on error -- a test
// convenience over the error-returning txcircuit.NewTransferP256ZoneCircuit.
func mustNewCircuit(shape txcircuit.Shape) *txcircuit.Circuit {
	circuit, err := txcircuit.NewTransferP256ZoneCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// mustNewSolanaCircuit builds the Solana-only circuit and panics on error.
func mustNewSolanaCircuit(shape txcircuit.Shape) *txcircuit.Circuit {
	circuit, err := txcircuit.NewTransferZoneCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func solveAssignment(t *testing.T, shape protocol.Shape, built proofAssignment) {
	t.Helper()
	var circuit *txcircuit.Circuit
	if built.circuit.RequiresP256 {
		circuit = mustNewCircuit(txcircuit.Shape(shape))
	} else {
		circuit = mustNewSolanaCircuit(txcircuit.Shape(shape))
	}
	if err := test.IsSolved(circuit, built.circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("assignment must solve the circuit: %v", err)
	}
}

// Spec UTXO Ownership: Ed25519 owners may differ per input. Each input's
// input_owner_pk_hashes entry carries its own owner's pk_field.
func TestBuildProofAssignmentAcceptsDistinctSolanaOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape, false)
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
	entries := built.publicInputs.InputOwnerPkHashes
	if entries[0].Sign() == 0 || entries[1].Sign() == 0 {
		t.Fatalf("both entries must be non-zero, got %v / %v", entries[0], entries[1])
	}
	if entries[0].Cmp(entries[1]) == 0 {
		t.Fatal("entries must differ for distinct owners")
	}
	if built.transcript.solanaOwnerPubkeys[0] == built.transcript.solanaOwnerPubkeys[1] {
		t.Fatal("transcript owner pubkeys must differ")
	}
	solveAssignment(t, shape, built)
}

// Spec UTXO Ownership: a P256-owned input (entry 0, bound to the shared
// witnessed signing key) and an Ed25519-owned input share one proof on the
// P256 rail.
func TestBuildProofAssignmentAcceptsMixedP256AndSolanaOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, payerHash, err := benchmarkTransaction(shape, false)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().ScalarBaseMult(big.NewInt(11).Bytes())
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	tx.Inputs[0].Utxo.OwnerSolanaPubkey = ""
	tx.Inputs[0].Utxo.OwnerP256Pubkey = parse.BytesHex(compressed)
	refreshStateEntry(t, &tx, 0)

	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{
		AllowMissingP256Signature: true,
	})
	if err != nil {
		t.Fatalf("mixed P256 + Solana owners must build: %v", err)
	}
	if !built.transcript.requiresP256OwnerWitness {
		t.Fatal("a P256-owned input must select the P256 rail")
	}
	entries := built.publicInputs.InputOwnerPkHashes
	if entries[0].Sign() != 0 {
		t.Fatalf("P256-owned input must carry entry 0, got %v", entries[0])
	}
	if entries[1].Sign() == 0 {
		t.Fatal("Ed25519-owned input must carry a non-zero entry")
	}
	if built.transcript.solanaOwnerPubkeys[0] != "" {
		t.Fatal("P256-owned input must have an empty owner pubkey entry")
	}
}
