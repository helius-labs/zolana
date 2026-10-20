package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/parse"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

type parsedInput struct {
	utxo            protocol.Utxo
	leafIndex       uint64
	nullifierSecret *big.Int
	ownerKeyHash    *big.Int
}

type inputWitnesses struct {
	inputs     []txcircuit.Input
	hashes     []*big.Int
	nullifiers []*big.Int
	// treeSlots is the slot index every input selected, in input order. It is
	// the private witness the packed InputFlags element publishes.
	treeSlots          []*big.Int
	inputOwnerPkHashes []*big.Int
}

// buildInputWitnesses fills every physical input slot, real spends first and
// padding dummies after. Every slot is hashed and nullified under trees.id, the
// raw id of the one tree this builder spends from, so the utxo hashes match the
// state entries SPP resolved for that tree, and every input selects the slot
// that tree is published in.
func buildInputWitnesses(
	shape protocol.Shape,
	requests []ProofInputRequest,
	state stateWitnesses,
	nullifierTree *protocol.NullifierTree,
	trees proofTrees,
	compactPadding bool,
) (inputWitnesses, error) {
	inputTreeID := trees.inputTreeID
	inputs := inputWitnesses{
		inputs:             make([]txcircuit.Input, shape.NInputs),
		hashes:             make([]*big.Int, shape.NInputs),
		nullifiers:         make([]*big.Int, shape.NInputs),
		treeSlots:          make([]*big.Int, shape.NInputs),
		inputOwnerPkHashes: make([]*big.Int, shape.NInputs),
	}
	for i := range inputs.treeSlots {
		inputs.treeSlots[i] = new(big.Int).Set(trees.inputTreeSlot)
	}

	for i, request := range requests {
		input, err := parseProofInput(request)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d: %w", i, err)
		}

		inputHash, err := protocol.UtxoHash(input.utxo, inputTreeID)
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

		witness := newInputWitness(inputs.treeSlots[i])
		witness.Utxo = toProofCircuitFields(input.utxo)
		witness.NullifierSecret = input.nullifierSecret
		inputs.inputOwnerPkHashes[i] = input.ownerKeyHash

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
		inputs.nullifiers[i] = nullifier
	}

	for i := len(requests); i < shape.NInputs; i++ {
		// Compact padding is a zero-blinding dummy that publishes nullifier 0.
		// Slot 0 stays a random dummy: its nullifier seeds the output blindings.
		compact := compactPadding && i > 0
		blinding := big.NewInt(0)
		if !compact {
			var err error
			if blinding, err = randomBlinding(); err != nil {
				return inputWitnesses{}, fmt.Errorf("dummy input %d blinding: %w", i, err)
			}
		}
		utxo := dummyUtxo(blinding)
		utxoHash, err := protocol.UtxoHash(utxo, inputTreeID)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d utxo hash: %w", i, err)
		}
		// A dummy derives its nullifier over the dummified utxo hash with
		// nullifier_secret = 0; the blinding is its sole source of
		// unpredictability. The circuit checks non-inclusion for every slot,
		// dummies included, so the dummy carries a real low-element witness.
		nullifier, err := protocol.Nullifier(utxoHash, blinding, big.NewInt(0))
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d nullifier: %w", i, err)
		}
		witness := dummyInputWitness(dummyUtxoFields(blinding), inputs.treeSlots[i])
		nfWitness, err := nullifierTree.NonInclusionWitness(nullifier)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d nullifier non-inclusion: %w", i, err)
		}
		witness.NullifierLowValue = nfWitness.LowValue
		witness.NullifierNextValue = nfWitness.NextValue
		fillPathElements(witness.NullifierLowPathElements, nfWitness.PathElements)
		witness.NullifierLowPathIndex = pathIndexVariable(nfWitness.LowIndex)
		inputs.inputs[i] = witness
		inputs.hashes[i] = big.NewInt(0)
		inputs.nullifiers[i] = nullifier
		if compact {
			inputs.nullifiers[i] = big.NewInt(0)
		}
		inputs.inputOwnerPkHashes[i] = big.NewInt(0)
	}
	return inputs, nil
}

// newInputWitness allocates one input slot selecting treeSlot. This builder
// spends from a single tree and the circuit rejects a slot whose roots are
// zero, so dummies must select the populated slot too.
func newInputWitness(treeSlot *big.Int) txcircuit.Input {
	return txcircuit.Input{
		StatePathElements:        zeroVariables(protocol.StateTreeHeight),
		StatePathIndex:           big.NewInt(0),
		TreeSlot:                 treeSlot,
		NullifierLowPathElements: zeroVariables(protocol.NullifierTreeHeight),
		NullifierLowPathIndex:    big.NewInt(0),
		NullifierLowValue:        big.NewInt(0),
		NullifierNextValue:       big.NewInt(0),
		NullifierSecret:          big.NewInt(0),
	}
}

// dummyInputWitness fills an unused input slot with a random-blinded UTXO so
// the public transcript is indistinguishable from a real input. Ownership and
// inclusion are skipped in-circuit; the caller attaches the real nullifier
// non-inclusion witness (checked for every slot) and publishes the derived
// dummy nullifier. A dummy shares its slot with the real inputs: its utxo hash
// and nullifier are derived under that slot's tree id, and its non-inclusion is
// proven against that slot's nullifier root.
func dummyInputWitness(utxo txcircuit.UtxoCircuitFields, treeSlot *big.Int) txcircuit.Input {
	witness := newInputWitness(treeSlot)
	witness.Utxo = utxo
	return witness
}

func parseProofInput(input ProofInputRequest) (parsedInput, error) {
	nullifierSecret, err := parse.Field(input.NullifierSecret)
	if err != nil {
		return parsedInput{}, fmt.Errorf("nullifier_secret: %w", err)
	}
	if strings.TrimSpace(input.Utxo.OwnerSolanaPubkey) == "" {
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
	}, nil
}
