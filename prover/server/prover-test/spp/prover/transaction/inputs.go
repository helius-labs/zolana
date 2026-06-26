package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type parsedInput struct {
	utxo              protocol.Utxo
	leafIndex         uint64
	nullifierSecret   *big.Int
	ownerKeyHash      *big.Int
	ownerSolanaPubkey string
	isP256            bool
}

type inputWitnesses struct {
	inputs                   []txcircuit.Input
	hashes                   []*big.Int
	utxoRoots                []*big.Int
	nullifierTreeRoots       []*big.Int
	nullifiers               []*big.Int
	inputOwnerPkHashes       []*big.Int
	solanaOwnerPubkeys       []string
	requiresP256OwnerWitness bool
}

func buildInputWitnesses(
	shape protocol.Shape,
	requests []ProofInputRequest,
	state stateWitnesses,
	nullifierTree *protocol.NullifierTree,
) (inputWitnesses, error) {
	inputs := inputWitnesses{
		inputs:             make([]txcircuit.Input, shape.NInputs),
		hashes:             make([]*big.Int, shape.NInputs),
		utxoRoots:          make([]*big.Int, shape.NInputs),
		nullifierTreeRoots: make([]*big.Int, shape.NInputs),
		nullifiers:         make([]*big.Int, shape.NInputs),
		inputOwnerPkHashes: make([]*big.Int, shape.NInputs),
		solanaOwnerPubkeys: make([]string, len(requests)),
	}

	for i, request := range requests {
		input, err := parseProofInput(request)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d: %w", i, err)
		}

		inputHash, err := protocol.UtxoHash(input.utxo)
		if err != nil {
			return inputWitnesses{}, err
		}
		if existing, ok := state.entries[input.leafIndex]; !ok || existing.Cmp(inputHash) != 0 {
			return inputWitnesses{}, fmt.Errorf("input %d leaf %d is not present in state_entries", i, input.leafIndex)
		}
		nullifier, err := protocol.Nullifier(inputHash, input.utxo.Blinding, input.nullifierSecret)
		if err != nil {
			return inputWitnesses{}, err
		}

		witness := newInputWitness()
		witness.Utxo = toProofCircuitFields(input.utxo)
		witness.NullifierSecret = input.nullifierSecret
		if input.isP256 {
			inputs.requiresP256OwnerWitness = true
			witness.OwnerPkHash = big.NewInt(0)
			inputs.inputOwnerPkHashes[i] = big.NewInt(0)
		} else {
			witness.OwnerPkHash = input.ownerKeyHash
			inputs.inputOwnerPkHashes[i] = input.ownerKeyHash
			inputs.solanaOwnerPubkeys[i] = input.ownerSolanaPubkey
		}
		utxoRoot := state.root
		nullifierTreeRoot := nullifierTree.Root()
		witness.Nullifier = nullifier
		witness.UtxoTreeRoot = utxoRoot
		witness.NullifierTreeRoot = nullifierTreeRoot

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
		inputs.nullifierTreeRoots[i] = nullifierTreeRoot
		inputs.nullifiers[i] = nullifier
	}

	for i := len(requests); i < shape.NInputs; i++ {
		blinding, err := randomBlinding()
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d blinding: %w", i, err)
		}
		utxo := dummyUtxo(blinding)
		utxoHash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d utxo hash: %w", i, err)
		}
		nullifierSecret, err := randomBlinding()
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d nullifier secret: %w", i, err)
		}
		nullifier, err := protocol.Nullifier(utxoHash, blinding, nullifierSecret)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d nullifier: %w", i, err)
		}
		witness := dummyInputWitness(dummyUtxoFields(blinding), nullifier)
		inputs.inputs[i] = witness
		inputs.hashes[i] = big.NewInt(0)
		inputs.utxoRoots[i] = big.NewInt(0)
		inputs.nullifierTreeRoots[i] = big.NewInt(0)
		inputs.nullifiers[i] = nullifier
		inputs.inputOwnerPkHashes[i] = big.NewInt(0)
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
		NullifierTreeRoot:        big.NewInt(0),
		OwnerPkHash:              big.NewInt(0),
		NullifierSecret:          big.NewInt(0),
	}
}

// dummyInputWitness fills an unused input slot with a random-blinded UTXO and
// derived nullifier so the public transcript is indistinguishable from a real
// input. Every spend check is skipped in-circuit; roots stay zero because the
// on-chain verifier treats missing root indices as zero.
func dummyInputWitness(utxo txcircuit.UtxoCircuitFields, nullifier *big.Int) txcircuit.Input {
	witness := newInputWitness()
	witness.IsDummy = big.NewInt(1)
	witness.Utxo = utxo
	witness.Nullifier = nullifier
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
		utxo:              parsed.utxo,
		leafIndex:         input.LeafIndex,
		nullifierSecret:   nullifierSecret,
		ownerKeyHash:      parsed.ownerKeyHash,
		ownerSolanaPubkey: parsed.normalized.OwnerSolanaPubkey,
		isP256:            parsed.isP256,
	}, nil
}
