package squads_ring_fold

import (
	"fmt"
	"math/big"

	foldcircuit "zolana/prover/circuits/squads/ring_fold"
	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Leg is one proved ring spend together with the preimage its public input
// chains. The prover binds the two rather than trusting the preimage.
type Leg struct {
	Proof         groth16.Proof
	PublicWitness witness.Witness

	Preimage []*big.Int
}

// ProveFold folds a run of spends of one account into one recursive proof.
//
// The legs are unchanged, so each stays valid for direct verification. They
// must already share a sender and a recipient and carry no proposal. A
// violation fails inside the circuit rather than here, because the circuit is
// what the program trusts.
func ProveFold(ps *common.SquadsRingFoldProofSystem, legs []Leg) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("fold proving system is not loaded")
	}
	if uint32(len(legs)) != ps.Legs {
		return nil, fmt.Errorf("%d legs against a fold of %d", len(legs), ps.Legs)
	}
	preimageLen := foldcircuit.PreimageLen(int(ps.NOutputs))

	assignment := &foldcircuit.Circuit{
		Proofs:     make([]foldcircuit.InnerProof, len(legs)),
		Witnesses:  make([]foldcircuit.InnerWitness, len(legs)),
		Preimages:  make([][]frontend.Variable, len(legs)),
		NumOutputs: int(ps.NOutputs),
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

	foldHash, err := FoldInputHash(legs, int(ps.NOutputs))
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

// FoldInputHash commits to the run. It covers the shared sender, the shared
// recipient on the transfer shape, then every leg's own transaction fields in
// leg order. The ring recomputes this from the accounts and the instruction, so
// the order here is part of the statement.
func FoldInputHash(legs []Leg, numOutputs int) (*big.Int, error) {
	if len(legs) == 0 {
		return nil, fmt.Errorf("empty fold")
	}
	preimageLen := foldcircuit.PreimageLen(numOutputs)
	for i, leg := range legs {
		if len(leg.Preimage) != preimageLen {
			return nil, fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(leg.Preimage), preimageLen)
		}
	}
	transfer := numOutputs == foldcircuit.TransferOutputs

	elements := []*big.Int{legs[0].Preimage[foldcircuit.SenderAccountIndex]}
	if transfer {
		elements = append(elements, legs[0].Preimage[foldcircuit.RecipientAccountIndex])
	}
	for _, leg := range legs {
		elements = append(elements,
			leg.Preimage[foldcircuit.PrivateTxHashIndex],
			leg.Preimage[foldcircuit.PublicAmountIndex],
			leg.Preimage[foldcircuit.SenderCiphertextIndex],
		)
		if transfer {
			elements = append(elements,
				leg.Preimage[foldcircuit.TxViewingPkLoIndex],
				leg.Preimage[foldcircuit.TxViewingPkHiIndex],
				leg.Preimage[foldcircuit.RecipientCiphertextIndex],
			)
		}
	}
	return common.HashChain(elements)
}
