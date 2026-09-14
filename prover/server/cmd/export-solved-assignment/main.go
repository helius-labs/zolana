package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover/common"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
)

func main() {
	keyPath := flag.String("key", "", "combined transfer proving key")
	requestPath := flag.String("request", "", "POST /prove request JSON")
	outputPath := flag.String("out", "", "assignment blob output")
	flag.Parse()
	if *keyPath == "" || *requestPath == "" || *outputPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*keyPath, *requestPath, *outputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(keyPath, requestPath, outputPath string) error {
	loaded, err := common.ReadSystemFromFile(keyPath)
	if err != nil {
		return fmt.Errorf("read proving key: %w", err)
	}
	proofSystem, ok := loaded.(*common.TransferProofSystem)
	if !ok {
		return fmt.Errorf("proving key contains %T, expected a transfer proof system", loaded)
	}
	request, err := os.ReadFile(requestPath)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	var parameters transfereddsaonly.TransferParameters
	if err := json.Unmarshal(request, &parameters); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if err := parameters.ValidateShape(); err != nil {
		return err
	}
	if proofSystem.NInputs != parameters.NInputs || proofSystem.NOutputs != parameters.NOutputs {
		return fmt.Errorf(
			"request shape %d→%d does not match key shape %d→%d",
			parameters.NInputs,
			parameters.NOutputs,
			proofSystem.NInputs,
			proofSystem.NOutputs,
		)
	}
	assignment, err := parameters.CreateWitness()
	if err != nil {
		return fmt.Errorf("create witness assignment: %w", err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("create witness: %w", err)
	}
	solved, err := proofSystem.ConstraintSystem.Solve(witness)
	if err != nil {
		return fmt.Errorf("solve constraints: %w", err)
	}
	solution, ok := solved.(*cs.R1CSSolution)
	if !ok {
		return fmt.Errorf("solver returned %T, expected an R1CS solution", solved)
	}
	if err := os.WriteFile(outputPath, encodeAssignment(
		proofSystem.ConstraintSystem.GetNbPublicVariables(),
		solution,
	), 0o644); err != nil {
		return fmt.Errorf("write assignment: %w", err)
	}
	return nil
}

func encodeAssignment(publicVariables int, solution *cs.R1CSSolution) []byte {
	size := 4*3 + fr.Bytes*(len(solution.W)+3*len(solution.A))
	encoded := make([]byte, 0, size)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(publicVariables))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(solution.W)))
	encoded = appendScalars(encoded, solution.W)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(solution.A)))
	encoded = appendScalars(encoded, solution.A)
	encoded = appendScalars(encoded, solution.B)
	encoded = appendScalars(encoded, solution.C)
	return encoded
}

func appendScalars(encoded []byte, values fr.Vector) []byte {
	for index := range values {
		value := values[index].Bytes()
		encoded = append(encoded, value[:]...)
	}
	return encoded
}
