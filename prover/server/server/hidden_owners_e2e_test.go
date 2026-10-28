package server

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

const hiddenOwnersRequest = "../prover/transfer_eddsa/testdata/eddsa-ring-2x2-h2.json"

// TestProveTwoHiddenOwnersOverHTTP sets up a key for the two-hidden-owner 2x2
// anonymous EdDSA circuit, proves the committed request through its key path
// as a client would, and verifies the returned proof against that key.
func TestProveTwoHiddenOwnersOverHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("groth16 setup of the two-hidden-owner 2x2 circuit")
	}
	body, err := os.ReadFile(hiddenOwnersRequest)
	if err != nil {
		t.Fatal(err)
	}
	var params transfer.AnonymousEddsaTransferParameters
	if err := json.Unmarshal(body, &params); err != nil {
		t.Fatal(err)
	}
	shape := params.ProofShape()
	want := common.ProofShape{
		Circuit:      common.TransferAnonymousRingEddsaCircuitType,
		Inputs:       2,
		Outputs:      2,
		HiddenOwners: 2,
	}
	if shape != want {
		t.Fatalf("request shape %s", shape)
	}

	keysDir := t.TempDir()
	system, err := transfer.SetupShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keysDir, shape.KeyFile())
	file, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := system.WriteTo(file); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	readiness := NewReadiness()
	readiness.MarkReady()
	mux := http.NewServeMux()
	registerProofPaths(mux, proveHandler{
		readiness:         readiness,
		keyManager:        common.NewLazyKeyManager(keysDir, &common.DownloadConfig{}),
		transferExecution: NewExecution(1),
		served:            servedKeys(t),
		admission:         newSyncAdmission(1),
	})

	// The protocol key's path refuses the body before anything loads.
	response := post(mux, "/prove/transfer_eddsa_ring_2_2", body)
	if response.Code != http.StatusBadRequest || errorCode(t, response) != "proving_key_mismatch" {
		t.Fatalf("protocol key path: got %d %q", response.Code, response.Body.String())
	}

	response = post(mux, "/prove/"+keyName(shape.KeyFile()), body)
	if response.Code != http.StatusOK {
		t.Fatalf("prove: got %d %q", response.Code, response.Body.String())
	}
	var proof common.Proof
	if err := json.Unmarshal(response.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.ProvingKeySha256 != sha256.Sum256(keyBytes) {
		t.Fatal("the proof does not report the key it was proved with")
	}

	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, system.VerifyingKey, public); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A different public input hash must not verify against the same proof.
	params.PublicInputHash = new(big.Int).Add(params.PublicInputHash, big.NewInt(1))
	tampered, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	tamperedPublic, err := frontend.NewWitness(tampered, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, system.VerifyingKey, tamperedPublic); err == nil {
		t.Fatal("the proof verified a different public input hash")
	}
}
