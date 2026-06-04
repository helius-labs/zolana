package nullifierbatchupdate

import (
	"math/big"
	"strings"
	"testing"

	"light/light-prover/prover/poseidon"
	nullifiercircuit "light/light-prover/prover/spp/circuit/nullifier_batch_update"
	"light/light-prover/prover/spp/model"

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
	inputs := []*big.Int{fe(1), fe(2), fe(3)}

	got, err := model.HashChain(inputs)
	if err != nil {
		t.Fatalf("hash chain: %v", err)
	}
	leftInner := mustPoseidon(t, 3, []*big.Int{fe(1), fe(2)})
	want := mustPoseidon(t, 3, []*big.Int{leftInner, fe(3)})
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

func fe(v int64) *big.Int {
	return big.NewInt(v)
}

func mustPoseidon(t *testing.T, width int, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.HashWithT(width, inputs)
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}
	return value
}
