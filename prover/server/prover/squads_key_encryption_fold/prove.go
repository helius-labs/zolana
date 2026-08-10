package squads_key_encryption_fold

import (
	"fmt"
	"math/big"

	foldcircuit "zolana/prover/circuits/squads/key_encryption_fold"
	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Leg is one proved key-encryption statement together with the preimage its
// public input chains. The prover binds the two rather than trusting the
// preimage.
type Leg struct {
	Proof         groth16.Proof
	PublicWitness witness.Witness

	Preimage []*big.Int
}

// ProveFold folds legs describing one account into one recursive proof.
//
// The legs are unchanged, so each stays valid for direct verification. They
// must already agree on the account's shared fields. A disagreement fails
// inside the circuit rather than here, because the circuit is what the program
// trusts.
func ProveFold(ps *common.SquadsKeyEncryptionFoldProofSystem, legs []Leg) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("fold proving system is not loaded")
	}
	if uint32(len(legs)) != ps.Legs {
		return nil, fmt.Errorf("%d legs against a fold of %d", len(legs), ps.Legs)
	}
	preimageLen := foldcircuit.PreimageLen(int(ps.KeysPerLeg))

	assignment := &foldcircuit.Circuit{
		Proofs:     make([]foldcircuit.InnerProof, len(legs)),
		Witnesses:  make([]foldcircuit.InnerWitness, len(legs)),
		Preimages:  make([][]frontend.Variable, len(legs)),
		KeysPerLeg: int(ps.KeysPerLeg),
	}
	for i, leg := range legs {
		if len(leg.Preimage) != preimageLen {
			return nil, fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(leg.Preimage), preimageLen)
		}
		proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.Proof)
		if err != nil {
			return nil, fmt.Errorf("leg %d proof: %w", i, err)
		}
		circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](leg.PublicWitness)
		if err != nil {
			return nil, fmt.Errorf("leg %d witness: %w", i, err)
		}
		claimed, err := common.HashChain(leg.Preimage)
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		proved, err := common.SinglePublicInput(leg.PublicWitness)
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		// Caught here so the caller sees which leg is mislabelled rather than an
		// unsatisfiable constraint system.
		if claimed.Cmp(proved) != 0 {
			return nil, fmt.Errorf("leg %d preimage does not match its public input", i)
		}

		assignment.Proofs[i], assignment.Witnesses[i] = proof, circuitWitness
		assignment.Preimages[i] = make([]frontend.Variable, preimageLen)
		for j, value := range leg.Preimage {
			assignment.Preimages[i][j] = value
		}
	}

	foldHash, err := FoldInputHash(legs, int(ps.KeysPerLeg))
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

// FoldInputHash is the chain a single key-encryption circuit over every leg's
// recipients would expose. The account's shared fields come once, then the
// recipient triples in leg order. The zone recomputes this from the account and
// the instruction, so the order here is part of the statement.
func FoldInputHash(legs []Leg, keysPerLeg int) (*big.Int, error) {
	if len(legs) == 0 {
		return nil, fmt.Errorf("empty fold")
	}
	preimageLen := foldcircuit.PreimageLen(keysPerLeg)
	keyEnd := foldcircuit.PrefixLen + foldcircuit.KeyFields*keysPerLeg

	elements := make([]*big.Int, 0, foldcircuit.PrefixLen+foldcircuit.KeyFields*keysPerLeg*len(legs)+foldcircuit.SuffixLen)
	for i, leg := range legs {
		if len(leg.Preimage) != preimageLen {
			return nil, fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(leg.Preimage), preimageLen)
		}
	}
	elements = append(elements, legs[0].Preimage[:foldcircuit.PrefixLen]...)
	for _, leg := range legs {
		elements = append(elements, leg.Preimage[foldcircuit.PrefixLen:keyEnd]...)
	}
	elements = append(elements, legs[0].Preimage[keyEnd:]...)
	return common.HashChain(elements)
}
