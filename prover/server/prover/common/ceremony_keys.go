package common

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
)

// BindCeremonyCommitment copies the constraint system's BSB22 commitment
// description onto a verifying key extracted from the phase-2 ceremony.
//
// The phase-2 extractor samples the Pedersen sigma when it writes the keys and
// stores the commitment keys, but it leaves PublicAndCommitmentCommitted empty.
// gnark's verifier counts commitments from that field, so an empty list rejects
// a key that actually has a commitment. The R1CS is the source of that list.
//
// A circuit with no commitments is left unchanged. A circuit with commitments
// requires the extracted proving and verifying keys to carry one commitment
// key each, from the same Pedersen setup.
func BindCeremonyCommitment(pk groth16.ProvingKey, vk groth16.VerifyingKey, cs constraint.ConstraintSystem) (int, error) {
	commits, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return 0, fmt.Errorf("constraint system commitments are %T", cs.GetCommitments())
	}
	if len(commits) == 0 {
		return 0, nil
	}

	provingKey, ok := pk.(*bn254groth16.ProvingKey)
	if !ok {
		return 0, fmt.Errorf("proving key is %T, want bn254", pk)
	}
	verifyingKey, ok := vk.(*bn254groth16.VerifyingKey)
	if !ok {
		return 0, fmt.Errorf("verifying key is %T, want bn254", vk)
	}
	if len(provingKey.CommitmentKeys) != len(commits) || len(verifyingKey.CommitmentKeys) != len(commits) {
		return 0, fmt.Errorf(
			"ceremony key has %d proving and %d verifying commitment keys, circuit has %d; rebuild the coordinator binary with coordinator/build_setup.sh",
			len(provingKey.CommitmentKeys), len(verifyingKey.CommitmentKeys), len(commits),
		)
	}
	verifyingKey.PublicAndCommitmentCommitted = commits.GetPublicAndCommitmentCommitted(
		commits.CommitmentIndexes(),
		cs.GetNbPublicVariables(),
	)
	return len(commits), nil
}
