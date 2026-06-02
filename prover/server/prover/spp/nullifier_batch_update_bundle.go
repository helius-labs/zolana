package spp

import (
	"encoding/json"
	"os"

	"light/light-prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

type NullifierBatchUpdateRequest struct {
	ExistingEntries []string `json:"existing_entries"`
	NewEntries      []string `json:"new_entries"`
}

type NullifierBatchUpdateBundle struct {
	Proof   *common.Proof `json:"proof"`
	NewRoot string        `json:"new_root"`
}

func WriteNullifierBatchUpdateBundle(ps *common.BatchProofSystem, requestPath string, outputPath string) error {
	bytes, err := os.ReadFile(requestPath)
	if err != nil {
		return err
	}
	var request NullifierBatchUpdateRequest
	if err := json.Unmarshal(bytes, &request); err != nil {
		return err
	}
	bundle, err := BuildNullifierBatchUpdateBundle(ps, request)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(outputPath, out, 0644)
}

func BuildNullifierBatchUpdateBundle(ps *common.BatchProofSystem, request NullifierBatchUpdateRequest) (*NullifierBatchUpdateBundle, error) {
	assignmentData, err := buildNullifierBatchUpdateAssignment(ps.TreeHeight, ps.BatchSize, request)
	if err != nil {
		return nil, err
	}
	assignment := assignmentData.toCircuit(ps.TreeHeight, ps.BatchSize)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, err
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	if err := groth16.Verify(proof, ps.VerifyingKey, publicWitness); err != nil {
		return nil, err
	}

	return &NullifierBatchUpdateBundle{
		Proof:   &common.Proof{Proof: proof},
		NewRoot: common.ToHex(assignmentData.newRoot),
	}, nil
}
