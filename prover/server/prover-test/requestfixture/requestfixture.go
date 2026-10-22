// Package requestfixture writes SPP /prove bodies that solve under the server's decode path.
package requestfixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/request"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

type Writer struct {
	directory string
}

// NewWriter skips the test without REQUEST_FIXTURES.
func NewWriter(t testing.TB) Writer {
	t.Helper()
	directory := os.Getenv("REQUEST_FIXTURES")
	if directory == "" {
		t.Skip("REQUEST_FIXTURES is unset")
	}
	return Writer{directory: directory}
}

func (w Writer) Write(t testing.TB, keyFile string, params any) {
	t.Helper()
	body, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := solve(keyFile, body); err != nil {
		t.Fatalf("%s: %v", keyFile, err)
	}
	if err := os.MkdirAll(w.directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.directory, strings.TrimSuffix(keyFile, ".key")+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// solve mirrors circuitProver.prove up to the proof.
func solve(keyFile string, body []byte) error {
	meta, err := common.ParseProofRequestMeta(body)
	if err != nil {
		return err
	}
	if meta.CircuitType == common.TransferAnonymousRingEddsaCircuitType {
		var params transfer.AnonymousEddsaTransferParameters
		if err := json.Unmarshal(body, &params); err != nil {
			return err
		}
		system, err := keySystem(keyFile, common.ProofShape{Circuit: meta.CircuitType, Inputs: params.NInputs, Outputs: params.NOutputs})
		if err != nil {
			return err
		}
		_, err = transfer.AnonymousEddsaProof{System: system, Parameters: &params, Prover: solveOnly}.Prove()
		return err
	}
	parsed, err := request.Parse(body)
	if err != nil {
		return err
	}
	system, err := keySystem(keyFile, common.ProofShape{Circuit: parsed.Circuit, Inputs: parsed.Inputs, Outputs: parsed.Outputs})
	if err != nil {
		return err
	}
	_, err = parsed.Prove(system, solveOnly)
	return err
}

func keySystem(keyFile string, shape common.ProofShape) (*common.TransferProofSystem, error) {
	if resolved := common.TransferKeyFile(shape.Circuit, shape.Inputs, shape.Outputs); resolved == "" || resolved != keyFile {
		return nil, fmt.Errorf("the body resolves to key %q", resolved)
	}
	ccs, err := request.R1CS(shape)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{CircuitType: shape.Circuit, NInputs: shape.Inputs, NOutputs: shape.Outputs, ConstraintSystem: ccs}, nil
}

// A BSB22 circuit solves only in a test binary, where gnark draws the commitment at random.
func solveOnly(ccs constraint.ConstraintSystem, _ groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error) {
	assignment, err := assign()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return nil, ccs.IsSolved(witness)
}
