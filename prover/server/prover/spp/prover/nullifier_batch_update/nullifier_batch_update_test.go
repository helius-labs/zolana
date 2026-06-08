package nullifierbatchupdate

import (
	"math/big"
	"strings"
	"testing"

	"light/light-prover/prover/poseidon"
	nullifiercircuit "light/light-prover/prover/spp/circuit/nullifier_batch_update"
	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestNullifierBatchUpdateCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	request := NullifierBatchUpdateRequest{
		NewEntries: []string{"0x1e", "0x0a"},
	}
	assignmentData, err := buildNullifierBatchUpdateAssignment(40, 2, request)
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}

	circuit := nullifiercircuit.NewCircuit(40, 2)
	witness := assignmentData.toCircuit(40, 2)
	assert.NoError(test.IsSolved(circuit, witness, ecc.BN254.ScalarField()))

	witness.HashchainHash = new(big.Int).Add(assignmentData.hashchainHash, big.NewInt(1))
	assert.Error(test.IsSolved(circuit, witness, ecc.BN254.ScalarField()))
}

func TestNullifierBatchUpdateUsesHashChain(t *testing.T) {
	inputs := []*big.Int{spptest.Fe(1), spptest.Fe(2), spptest.Fe(3)}

	got, err := protocol.HashChain(inputs)
	if err != nil {
		t.Fatalf("hash chain: %v", err)
	}
	leftInner := spptest.MustPoseidon(t, 3, []*big.Int{spptest.Fe(1), spptest.Fe(2)})
	want := spptest.MustPoseidon(t, 3, []*big.Int{leftInner, spptest.Fe(3)})
	if got.Cmp(want) != 0 {
		t.Fatalf("left-fold mismatch: got %s want %s", got, want)
	}
}

func TestNullifierBatchUpdateSeedsExistingEntries(t *testing.T) {
	request := NullifierBatchUpdateRequest{
		ExistingEntries: []string{"0x1e", "0x0a"},
		NewEntries:      []string{"0x14"},
	}
	assignmentData, err := buildNullifierBatchUpdateAssignment(40, 1, request)
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	if assignmentData.startIndex != 3 {
		t.Fatalf("start index mismatch: got %d want 3", assignmentData.startIndex)
	}
	if assignmentData.lowElementValues[0].Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", assignmentData.lowElementValues[0])
	}
	if assignmentData.lowElementNextValues[0].Cmp(big.NewInt(30)) != 0 {
		t.Fatalf("next value mismatch: got %s want 30", assignmentData.lowElementNextValues[0])
	}
}

func TestNullifierBatchUpdateRejectsDuplicateEntries(t *testing.T) {
	_, err := buildNullifierBatchUpdateAssignment(40, 2, NullifierBatchUpdateRequest{
		NewEntries: []string{"0x0a", "0x0a"},
	})
	if err == nil {
		t.Fatal("expected duplicate nullifier update entry to fail")
	}
}

func TestNullifierBatchUpdateCircuitRejectsDuplicateValueWithinBatch(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentData, err := buildNullifierBatchUpdateAssignment(40, 2, NullifierBatchUpdateRequest{
		NewEntries: []string{"0x0a", "0x1e"},
	})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	assignmentData.newElementValues[1] = new(big.Int).Set(assignmentData.newElementValues[0])
	refreshNullifierBatchPublicInputs(t, assignmentData)

	circuit := nullifiercircuit.NewCircuit(40, 2)
	witness := assignmentData.toCircuit(40, 2)
	assert.Error(test.IsSolved(circuit, witness, ecc.BN254.ScalarField()))
}

func TestNullifierBatchUpdateUsesSentinelNextValue(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentData, err := buildNullifierBatchUpdateAssignment(40, 1, NullifierBatchUpdateRequest{
		ExistingEntries: []string{"0x0a"},
		NewEntries:      []string{"0x1e"},
	})
	if err != nil {
		t.Fatalf("build assignment: %v", err)
	}
	wantSentinel := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	if assignmentData.lowElementValues[0].Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", assignmentData.lowElementValues[0])
	}
	if assignmentData.lowElementNextValues[0].Cmp(wantSentinel) != 0 {
		t.Fatalf("next value mismatch: got %s want sentinel", assignmentData.lowElementNextValues[0])
	}

	circuit := nullifiercircuit.NewCircuit(40, 1)
	assert.NoError(test.IsSolved(circuit, assignmentData.toCircuit(40, 1), ecc.BN254.ScalarField()))
}

func TestNullifierBatchUpdateWitnessRejectsFullSubtree(t *testing.T) {
	tree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatalf("new nullifier tree: %v", err)
	}
	if _, err := tree.InsertWithWitness(big.NewInt(10), 1); err != nil {
		t.Fatalf("insert first value: %v", err)
	}
	_, err = tree.InsertWithWitness(big.NewInt(30), 1)
	if err == nil || !strings.Contains(err.Error(), "exceeds 2^1") {
		t.Fatalf("full subtree error = %v", err)
	}
}

func TestNullifierBatchUpdateRejectsBadShape(t *testing.T) {
	_, err := buildNullifierBatchUpdateAssignment(39, 1, NullifierBatchUpdateRequest{
		NewEntries: []string{"0x0a"},
	})
	if err == nil || !strings.Contains(err.Error(), "tree height 39") {
		t.Fatalf("tree height error = %v", err)
	}

	_, err = buildNullifierBatchUpdateAssignment(40, 2, NullifierBatchUpdateRequest{
		NewEntries: []string{"0x0a"},
	})
	if err == nil || !strings.Contains(err.Error(), "new_entries length 1") {
		t.Fatalf("batch size error = %v", err)
	}
}

func TestNullifierBatchUpdateRejectsMalformedEntries(t *testing.T) {
	_, err := buildNullifierBatchUpdateAssignment(40, 1, NullifierBatchUpdateRequest{
		ExistingEntries: []string{"0xzz"},
		NewEntries:      []string{"0x0a"},
	})
	if err == nil || !strings.Contains(err.Error(), "existing_entries[0]") {
		t.Fatalf("existing entry error = %v", err)
	}

	_, err = buildNullifierBatchUpdateAssignment(40, 1, NullifierBatchUpdateRequest{
		NewEntries: []string{"0xzz"},
	})
	if err == nil || !strings.Contains(err.Error(), "new_entries[0]") {
		t.Fatalf("new entry error = %v", err)
	}
}

func refreshNullifierBatchPublicInputs(t *testing.T, assignment *nullifierBatchUpdateAssignment) {
	t.Helper()
	assignment.hashchainHash = spptest.MustHashChain(t, assignment.newElementValues)
	assignment.publicInputHash = spptest.MustHashChain(t, []*big.Int{
		assignment.oldRoot,
		assignment.newRoot,
		assignment.hashchainHash,
		new(big.Int).SetUint64(assignment.startIndex),
	})
}
