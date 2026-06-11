package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

type parsedInput struct {
	utxo            protocol.Utxo
	leafIndex       uint64
	nullifierSecret *big.Int
	ownerKeyHash    *big.Int
	isP256          bool
}

type inputWitnesses struct {
	inputs                   []txcircuit.Input
	hashes                   []*big.Int
	utxoRoots                []*big.Int
	nullifierRoots           []*big.Int
	nullifiers               []*big.Int
	solanaPkHashes           []*big.Int
	solanaOwnerInputIndices  []int
	requiresP256OwnerWitness bool
	nullifierSecret          *big.Int
}

func buildInputWitnesses(
	shape protocol.Shape,
	requests []ProofInputRequest,
	state stateWitnesses,
	nullifierTree *protocol.NullifierTree,
) (inputWitnesses, error) {
	inputs := inputWitnesses{
		inputs:                  make([]txcircuit.Input, shape.NInputs),
		hashes:                  make([]*big.Int, shape.NInputs),
		utxoRoots:               make([]*big.Int, shape.NInputs),
		nullifierRoots:          make([]*big.Int, shape.NInputs),
		nullifiers:              make([]*big.Int, shape.NInputs),
		solanaPkHashes:          make([]*big.Int, shape.NInputs),
		solanaOwnerInputIndices: make([]int, 0, len(requests)),
		nullifierSecret:         big.NewInt(0),
	}

	for i, request := range requests {
		input, err := parseProofInput(request)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d: %w", i, err)
		}
		if i == 0 {
			inputs.nullifierSecret = input.nullifierSecret
		} else if inputs.nullifierSecret.Cmp(input.nullifierSecret) != 0 {
			return inputWitnesses{}, fmt.Errorf("input %d nullifier_secret differs from input 0", i)
		}

		inputHash, err := protocol.UtxoHash(input.utxo)
		if err != nil {
			return inputWitnesses{}, err
		}
		if existing, ok := state.entries[input.leafIndex]; !ok || existing.Cmp(inputHash) != 0 {
			return inputWitnesses{}, fmt.Errorf("input %d leaf %d is not present in state_entries", i, input.leafIndex)
		}
		nullifier, err := protocol.NullifierHash(inputHash, input.utxo.Blinding, input.nullifierSecret)
		if err != nil {
			return inputWitnesses{}, err
		}

		witness := newInputWitness()
		witness.Utxo = toProofCircuitFields(input.utxo)
		if input.isP256 {
			witness.SolanaPkHash = big.NewInt(0)
			inputs.solanaPkHashes[i] = big.NewInt(0)
			inputs.requiresP256OwnerWitness = true
		} else {
			witness.SolanaPkHash = input.ownerKeyHash
			inputs.solanaPkHashes[i] = input.ownerKeyHash
			inputs.solanaOwnerInputIndices = append(inputs.solanaOwnerInputIndices, i)
		}
		utxoRoot := state.root
		nullifierRoot := nullifierTree.Root()
		witness.Nullifier = nullifier
		witness.UtxoTreeRoot = utxoRoot
		witness.NullifierRoot = nullifierRoot

		proof, ok := state.proofs[input.leafIndex]
		if !ok {
			return inputWitnesses{}, fmt.Errorf("missing state proof for leaf %d", input.leafIndex)
		}
		fillPathElements(witness.StatePathElements, proof.PathElements)
		witness.StatePathIndex = pathIndexVariable(proof.PathIndex)

		nfWitness, err := nullifierTree.NonInclusionWitness(nullifier)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d nullifier non-inclusion: %w", i, err)
		}
		witness.NullifierLowValue = nfWitness.LowValue
		witness.NullifierNextValue = nfWitness.NextValue
		fillPathElements(witness.NullifierLowPathElements, nfWitness.PathElements)
		witness.NullifierLowPathIndex = pathIndexVariable(nfWitness.LowIndex)

		inputs.inputs[i] = witness
		inputs.hashes[i] = inputHash
		inputs.utxoRoots[i] = utxoRoot
		inputs.nullifierRoots[i] = nullifierRoot
		inputs.nullifiers[i] = nullifier
	}

	for i := len(requests); i < shape.NInputs; i++ {
		inputs.inputs[i] = dummyInputWitness()
		inputs.hashes[i] = big.NewInt(0)
		inputs.utxoRoots[i] = big.NewInt(0)
		inputs.nullifierRoots[i] = big.NewInt(0)
		inputs.nullifiers[i] = big.NewInt(0)
		inputs.solanaPkHashes[i] = big.NewInt(0)
	}
	return inputs, nil
}

func newInputWitness() txcircuit.Input {
	return txcircuit.Input{
		IsDummy:                  big.NewInt(0),
		StatePathElements:        zeroVariables(protocol.StateTreeHeight),
		StatePathIndex:           big.NewInt(0),
		NullifierLowPathElements: zeroVariables(protocol.NullifierTreeHeight),
		NullifierLowPathIndex:    big.NewInt(0),
		NullifierLowValue:        big.NewInt(0),
		NullifierNextValue:       big.NewInt(0),
		UtxoTreeRoot:             big.NewInt(0),
		NullifierRoot:            big.NewInt(0),
	}
}

// dummyInputWitness fills an unused input slot. Every spend check is skipped for
// it in-circuit; it contributes nullifier 0, SolanaPkHash 0, and zero roots to
// the public transcript. Zero roots match the on-chain verifier, which
// reconstructs a slot's root as zero when no root index is supplied for it (a
// dummy slot).
func dummyInputWitness() txcircuit.Input {
	witness := newInputWitness()
	witness.IsDummy = big.NewInt(1)
	witness.Utxo = dummyUtxoFields()
	witness.SolanaPkHash = big.NewInt(0)
	witness.Nullifier = big.NewInt(0)
	return witness
}

func parseProofInput(input ProofInputRequest) (parsedInput, error) {
	nullifierSecret, err := parse.Field(input.NullifierSecret)
	if err != nil {
		return parsedInput{}, fmt.Errorf("nullifier_secret: %w", err)
	}
	if strings.TrimSpace(input.Utxo.OwnerSolanaPubkey) == "" && strings.TrimSpace(input.Utxo.OwnerP256Pubkey) == "" {
		return parsedInput{}, fmt.Errorf("input owner components are required")
	}
	parsed, err := parseProofUtxo(input.Utxo, nullifierSecret)
	if err != nil {
		return parsedInput{}, err
	}
	return parsedInput{
		utxo:            parsed.utxo,
		leafIndex:       input.LeafIndex,
		nullifierSecret: nullifierSecret,
		ownerKeyHash:    parsed.ownerKeyHash,
		isP256:          parsed.isP256,
	}, nil
}
