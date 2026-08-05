package aggregate

import (
	"fmt"
	"math/big"

	aggregatecircuit "zolana/prover/circuits/spp_aggregate"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Leg is one batched proof together with the public witness it proves.
type Leg struct {
	Proof         groth16.Proof
	PublicWitness witness.Witness
}

// ProveAggregate batches the legs into one recursive proof.
//
// The legs are unchanged. Batching does not re-prove them, so a leg stays valid
// for direct submission.
func ProveAggregate(ps *common.AggregateProofSystem, legs []Leg) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("aggregate proving system is not loaded")
	}
	if uint32(len(legs)) != ps.Batch() {
		return nil, fmt.Errorf("%d legs against a batch of %d", len(legs), ps.Batch())
	}

	full, err := legsWitness(legs)
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}

// legsWitness builds the full outer witness for a batch of legs. Both the CPU
// and the GPU prover consume it, so the statement they prove is one code path.
func legsWitness(legs []Leg) (witness.Witness, error) {
	assignment := &aggregatecircuit.Circuit{
		Proofs:    make([]aggregatecircuit.InnerProof, len(legs)),
		Witnesses: make([]aggregatecircuit.InnerWitness, len(legs)),
	}
	hashes := make([]*big.Int, len(legs))
	for i, leg := range legs {
		proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.Proof)
		if err != nil {
			return nil, fmt.Errorf("leg %d proof: %w", i, err)
		}
		circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](leg.PublicWitness)
		if err != nil {
			return nil, fmt.Errorf("leg %d witness: %w", i, err)
		}
		if hashes[i], err = common.SinglePublicInput(leg.PublicWitness); err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		assignment.Proofs[i], assignment.Witnesses[i] = proof, circuitWitness
	}

	aggregateHash, err := AggregateInputHash(hashes)
	if err != nil {
		return nil, err
	}
	assignment.AggregateInputHash = aggregateHash

	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	return full, nil
}

// AggregateInputHash folds the leg public inputs the way the outer circuit and
// the shielded pool fold them, a Poseidon left fold in batch order.
func AggregateInputHash(hashes []*big.Int) (*big.Int, error) {
	return common.HashChain(hashes)
}
