package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
)

type proofFixture struct {
	Proof       *common.Proof `json:"proof"`
	PublicInput string        `json:"publicInput"`
	ProveMs     float64       `json:"proveMs"`
}

// TestRequestFixturesProveUnderTheirLockedKeys proves every /prove body under the key its file names and writes <key stem>.proof.json:
//
//	REQUEST_FIXTURES=<bodies> PROVING_KEYS=<keys> PROOF_FIXTURES=<dir> go test ./server -run TestRequestFixturesProveUnderTheirLockedKeys -count 1 -timeout 0
func TestRequestFixturesProveUnderTheirLockedKeys(t *testing.T) {
	bodies, keys, proofs := os.Getenv("REQUEST_FIXTURES"), os.Getenv("PROVING_KEYS"), os.Getenv("PROOF_FIXTURES")
	if bodies == "" || keys == "" || proofs == "" {
		t.Skip("REQUEST_FIXTURES, PROVING_KEYS and PROOF_FIXTURES are unset")
	}
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(bodies, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("%s holds no /prove body", bodies)
	}
	if err := os.MkdirAll(proofs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		stem := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(stem, func(t *testing.T) {
			t.Parallel()
			keyFile := stem + ".key"
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			trace := timing.New()
			proof, failure := circuitProver{
				keys:      common.NewLazyKeyManager(keys, &common.DownloadConfig{}),
				trace:     trace,
				admission: keyAdmission{expected: keyFile},
			}.prove(payload)
			if failure != nil {
				t.Fatal(loggedCause(failure))
			}
			// EnsureProvingKey admits an unpinned key file unchecked.
			if pinned := manifest.Keys[keyFile].Sha256; hex.EncodeToString(proof.ProvingKeySha256[:]) != pinned {
				t.Fatalf("proved with sha256 %x, the lock pins %q", proof.ProvingKeySha256, pinned)
			}
			publicInputHash, err := publicInput(payload)
			if err != nil {
				t.Fatal(err)
			}
			public, err := publicWitness(publicInputHash)
			if err != nil {
				t.Fatal(err)
			}
			verifying, err := verifyingKey(filepath.Join(keys, keyFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof.Proof, verifying, public); err != nil {
				t.Fatal(err)
			}
			spans := trace.Snapshot()
			prove := slices.IndexFunc(spans, func(span timing.Span) bool { return span.Name == "prove" })
			if prove < 0 {
				t.Fatal("the trace holds no prove span")
			}
			encoded, err := json.MarshalIndent(proofFixture{
				// The verifier reads no key digest.
				Proof:       &common.Proof{Proof: proof.Proof},
				PublicInput: common.ToHex(publicInputHash),
				ProveMs:     spans[prove].DurationMS,
			}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proofs, stem+".proof.json"), append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// publicInput is the single public input of every circuit a body proves.
func publicInput(payload []byte) (*big.Int, error) {
	var request struct {
		PublicInputHash string `json:"publicInputHash"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, err
	}
	return common.FeFromHex(request.PublicInputHash)
}

func publicWitness(publicInputHash *big.Int) (witness.Witness, error) {
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	values := make(chan any, 1)
	values <- publicInputHash
	close(values)
	return public, public.Fill(1, 0, values)
}

// verifyingKey reads the verifying key export-vk exports from a key file.
func verifyingKey(path string) (groth16.VerifyingKey, error) {
	system, err := common.ReadSystemFromFile(path)
	if err != nil {
		return nil, err
	}
	switch system := system.(type) {
	case *common.TransferProofSystem:
		return system.VerifyingKey, nil
	case *common.RingProofSystem:
		return system.VerifyingKey, nil
	}
	return nil, fmt.Errorf("%T proves no /prove body", system)
}
