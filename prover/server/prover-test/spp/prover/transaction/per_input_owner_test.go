package transaction

import (
	"math/big"
	"testing"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/parse"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// refreshStateEntry recomputes the state-tree leaf for an input whose owner
// was mutated, so the witness builder reaches the owner checks instead of
// failing the leaf lookup. The leaf is hashed under the request's input tree
// id, the same id the builder binds the input to.
func refreshStateEntry(t *testing.T, tx *ProofTransactionRequest, i int) {
	t.Helper()
	parsed, err := parseProofInput(tx.Inputs[i])
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocol.UtxoHash(parsed.utxo, big.NewInt(int64(tx.InputTreeID)))
	if err != nil {
		t.Fatal(err)
	}
	tx.StateEntries[i].Hash = proofFieldInput(hash)
}

// mustNewSolanaCircuit builds the Solana-only circuit and panics on error.
func mustNewSolanaCircuit(shape txcircuit.Shape) *customring.CustomRingConfidentialEd25519Circuit {
	circuit, err := customring.NewCustomRingConfidentialEd25519Circuit(shape)
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
// private while the public signer transcript contains each owner, and not the
// fee payer as such.
func TestBuildProofAssignmentAcceptsDistinctSolanaOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	tx, _, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	var otherOwner [32]byte
	for i := range otherOwner {
		otherOwner[i] = byte(i + 101)
	}
	tx.Inputs[1].Utxo.OwnerSolanaPubkey = parse.BytesHex(otherOwner[:])
	refreshStateEntry(t, &tx, 1)

	built, err := buildProofAssignment(shape, tx, proofBuildOptions{})
	if err != nil {
		t.Fatalf("distinct Solana owners must build: %v", err)
	}
	entries := built.publicInputs.SignerPkHashes
	if entries[0].Sign() == 0 {
		t.Fatalf("first owner signer entry must be non-zero, got %v", entries[0])
	}
	if entries[1].Sign() == 0 {
		t.Fatalf("second owner signer entry must be non-zero, got %v", entries[1])
	}
	if entries[2].Sign() != 0 {
		t.Fatalf("unused signer entry must be zero, got %v", entries[2])
	}
	if built.transcript.solanaOwnerPubkeys[0] == built.transcript.solanaOwnerPubkeys[1] {
		t.Fatal("transcript owner pubkeys must differ")
	}
	solveAssignment(t, shape, built)
}

// Legacy key fields must not bypass owner validation through an explicit commitment.
func TestRejectRemovedOwnerKey(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		input := ProofUtxoRequest{OwnerP256Pubkey: "0x02"}
		if explicit {
			input.Owner = "1"
		}
		if _, err := parseOwner(input, big.NewInt(1)); err == nil {
			t.Fatal("removed owner key accepted")
		}
		if _, err := ownerComponents(input, big.NewInt(1)); err == nil {
			t.Fatal("removed owner components accepted")
		}
	}
}
