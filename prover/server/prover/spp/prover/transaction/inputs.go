package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

type parsedInput struct {
	utxo            model.Utxo
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
	shape model.Shape,
	requests []ProofInputRequest,
	state stateWitnesses,
	nullifierTree *model.IndexedTree,
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

		inputHash, err := model.UtxoHash(input.utxo)
		if err != nil {
			return inputWitnesses{}, err
		}
		if existing, ok := state.entries[input.leafIndex]; !ok || existing.Cmp(inputHash) != 0 {
			return inputWitnesses{}, fmt.Errorf("input %d leaf %d is not present in state_entries", i, input.leafIndex)
		}
		nullifier, err := model.NullifierHash(inputHash, input.utxo.Blinding, input.nullifierSecret)
		if err != nil {
			return inputWitnesses{}, err
		}

		witness := emptyInput()
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
		fillProofPath(witness.StatePath, witness.StatePathDirs, proof.Siblings, proof.Directions)

		nfWitness, err := nullifierTree.NonInclusionChecked(nullifier)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d nullifier non-inclusion: %w", i, err)
		}
		witness.NfLowValue = nfWitness.LowValue
		witness.NfNextValue = nfWitness.NextValue
		fillProofPath(witness.NfLowPath, witness.NfLowPathDirs, nfWitness.Siblings, nfWitness.Directions)

		inputs.inputs[i] = witness
		inputs.hashes[i] = inputHash
		inputs.utxoRoots[i] = utxoRoot
		inputs.nullifierRoots[i] = nullifierRoot
		inputs.nullifiers[i] = nullifier
	}
	return inputs, nil
}

func emptyInput() txcircuit.Input {
	return txcircuit.Input{
		StatePath:     zeroVariables(model.StateTreeHeight),
		StatePathDirs: zeroVariables(model.StateTreeHeight),
		NfLowPath:     zeroVariables(model.NullifierTreeHeight),
		NfLowPathDirs: zeroVariables(model.NullifierTreeHeight),
		NfLowValue:    big.NewInt(0),
		NfNextValue:   big.NewInt(0),
		UtxoTreeRoot:  big.NewInt(0),
		NullifierRoot: big.NewInt(0),
	}
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
