package requestfixture

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

const confidentialRequest = "../../prover/request/testdata/transfer-2x2.json"

func committedRequest(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSolveAcceptsTheCommittedConfidentialRequest(t *testing.T) {
	if err := solve("transfer_confidential_2_2.key", committedRequest(t, confidentialRequest)); err != nil {
		t.Fatal(err)
	}
}

func TestSolveAcceptsTheCommittedEddsaRingRequest(t *testing.T) {
	if err := solve("transfer_eddsa_ring_2_2.key", committedRequest(t, "../../prover/transfer_eddsa/testdata/eddsa-ring-2x2.json")); err != nil {
		t.Fatal(err)
	}
}

func TestSolveRefusesABodyUnderAnotherKeyFile(t *testing.T) {
	err := solve("transfer_confidential_2_4.key", committedRequest(t, confidentialRequest))
	if err == nil || !strings.Contains(err.Error(), `resolves to key "transfer_confidential_2_2.key"`) {
		t.Fatalf("a 2x2 body passed as the 2x4 key: %v", err)
	}
}

func TestSolveRefusesAMutatedPublicInputHash(t *testing.T) {
	var params transfer.TransferParameters
	if err := json.Unmarshal(committedRequest(t, confidentialRequest), &params); err != nil {
		t.Fatal(err)
	}
	params.PublicInputHash = new(big.Int).Add(params.PublicInputHash, big.NewInt(1))
	body, err := json.Marshal(&params)
	if err != nil {
		t.Fatal(err)
	}
	if err := solve("transfer_confidential_2_2.key", body); err == nil || !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("a mutated public input hash solved: %v", err)
	}
}
