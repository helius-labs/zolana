package nullifier_fold

import (
	"fmt"
	"math/big"

	foldcircuit "zolana/prover/circuits/nullifier_fold"
	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// Append is one proved zkp-batch together with the span it advanced. The span
// fields are the append circuit's public-input preimage, so the fold binds them
// to the proof rather than trusting them.
type Append struct {
	Proof         groth16.Proof
	PublicWitness witness.Witness

	OldRoot       *big.Int
	NewRoot       *big.Int
	HashchainHash *big.Int
	StartIndex    *big.Int
}

func (a Append) preimage() []*big.Int {
	return []*big.Int{a.OldRoot, a.NewRoot, a.HashchainHash, a.StartIndex}
}

// ProveFold folds a consecutive run of appends into one recursive proof.
//
// The appends are unchanged, so each stays valid for direct submission. The run
// must already be consecutive. A gap fails inside the circuit rather than here,
// because the program trusts only the circuit.
func ProveFold(ps *common.NullifierFoldProofSystem, run []Append) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("fold proving system is not loaded")
	}
	if uint32(len(run)) != ps.Run {
		return nil, fmt.Errorf("%d appends against a run of %d", len(run), ps.Run)
	}

	assignment := &foldcircuit.Circuit{
		Proofs:    make([]foldcircuit.InnerProof, len(run)),
		Witnesses: make([]foldcircuit.InnerWitness, len(run)),
		Preimages: make([][foldcircuit.PreimageLen]frontend.Variable, len(run)),
		BatchSize: int(ps.BatchSize),
	}
	for i, leg := range run {
		proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.Proof)
		if err != nil {
			return nil, fmt.Errorf("append %d proof: %w", i, err)
		}
		circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](leg.PublicWitness)
		if err != nil {
			return nil, fmt.Errorf("append %d witness: %w", i, err)
		}
		preimage := leg.preimage()
		claimed, err := HashChain(preimage)
		if err != nil {
			return nil, fmt.Errorf("append %d: %w", i, err)
		}
		proved, err := publicInputHash(leg.PublicWitness)
		if err != nil {
			return nil, fmt.Errorf("append %d: %w", i, err)
		}
		// Caught here so the caller sees which append is mislabelled rather
		// than an unsatisfiable constraint system.
		if claimed.Cmp(proved) != 0 {
			return nil, fmt.Errorf("append %d span does not match its public input", i)
		}

		assignment.Proofs[i], assignment.Witnesses[i] = proof, circuitWitness
		for j, value := range preimage {
			assignment.Preimages[i][j] = value
		}
	}

	foldHash, err := FoldInputHash(run)
	if err != nil {
		return nil, err
	}
	assignment.FoldInputHash = foldHash

	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	proof, err := gpuprove.Prove(ps.ConstraintSystem, ps.ProvingKey, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}

// FoldInputHash commits to the span the run advanced. It binds the endpoints,
// every leg's element chain, and the start index. The forester program
// recomputes this from the instruction, so the order here is part of the
// statement.
func FoldInputHash(run []Append) (*big.Int, error) {
	if len(run) == 0 {
		return nil, fmt.Errorf("empty run")
	}
	elements := make([]*big.Int, len(run))
	for i, leg := range run {
		elements[i] = leg.HashchainHash
	}
	chain, err := HashChain(elements)
	if err != nil {
		return nil, err
	}
	return HashChain([]*big.Int{
		run[0].OldRoot,
		run[len(run)-1].NewRoot,
		chain,
		run[0].StartIndex,
	})
}

// HashChain folds Poseidon left to right, matching the circuit gadget and the
// program's create_hash_chain_from_slice.
func HashChain(values []*big.Int) (*big.Int, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("empty hash chain")
	}
	acc := values[0]
	for _, next := range values[1:] {
		folded, err := poseidon.Hash([]*big.Int{acc, next})
		if err != nil {
			return nil, fmt.Errorf("hash chain: %w", err)
		}
		acc = folded
	}
	return acc, nil
}

func publicInputHash(public witness.Witness) (*big.Int, error) {
	vector, ok := public.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("public witness is %T, want a BN254 vector", public.Vector())
	}
	if len(vector) != 1 {
		return nil, fmt.Errorf("%d public inputs, want 1", len(vector))
	}
	value := new(big.Int)
	vector[0].BigInt(value)
	return value, nil
}
