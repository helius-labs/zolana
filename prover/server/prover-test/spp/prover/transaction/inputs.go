package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
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
	inputs []txcircuit.Input
	// spendKeys[i] is nil for slots that do not sign (dummies and P256-owned
	// inputs); SignSpendWitnesses skips those.
	spendKeys                []*protocol.SpendKey
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
		spendKeys:          make([]*protocol.SpendKey, shape.NInputs),
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

		spendKey, err := protocol.NewSpendKey(input.nullifierSecret)
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("input %d spend key: %w", i, err)
		}
		witness := newInputWitness()
		witness.Utxo = toProofCircuitFields(input.utxo)
		witness.NullifierSecret = input.nullifierSecret
		witness.SpendPublic.A.X = spendKey.Public.X
		witness.SpendPublic.A.Y = spendKey.Public.Y
		inputs.spendKeys[i] = &spendKey
		if input.isP256 {
			inputs.requiresP256OwnerWitness = true
			inputs.inputOwnerPkHashes[i] = big.NewInt(0)
		} else {
			inputs.inputOwnerPkHashes[i] = input.ownerKeyHash
			inputs.solanaOwnerPubkeys[i] = input.ownerSolanaPubkey
		}
		utxoRoot := state.root
		nullifierTreeRoot := nullifierTree.Root()

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
		// A dummy derives its nullifier over the dummified utxo hash with
		// nullifier_secret = 0; the blinding is its sole source of
		// unpredictability. The circuit checks non-inclusion for every slot,
		// dummies included, so the dummy carries a real low-element witness.
		nullifier, err := protocol.Nullifier(utxoHash, blinding, big.NewInt(0))
		if err != nil {
			return inputWitnesses{}, fmt.Errorf("dummy input %d nullifier: %w", i, err)
		}
		witness := dummyInputWitness(dummyUtxoFields(blinding))
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
		inputs.utxoRoots[i] = big.NewInt(0)
		inputs.nullifierTreeRoots[i] = nullifierTree.Root()
		inputs.nullifiers[i] = nullifier
		inputs.inputOwnerPkHashes[i] = big.NewInt(0)
	}
	return inputs, nil
}

func newInputWitness() txcircuit.Input {
	input := txcircuit.Input{
		StatePathElements:        zeroVariables(protocol.StateTreeHeight),
		StatePathIndex:           big.NewInt(0),
		NullifierLowPathElements: zeroVariables(protocol.NullifierTreeHeight),
		NullifierLowPathIndex:    big.NewInt(0),
		NullifierLowValue:        big.NewInt(0),
		NullifierNextValue:       big.NewInt(0),
		NullifierSecret:          big.NewInt(0),
	}
	// A slot defaults to the non-signing convention: the neutral element and the
	// signature that verifies under it. Zeroed coordinates would be off the
	// curve and make the whole witness unsatisfiable.
	assignSpendWitness(&input, protocol.IdentitySpendPoint(), protocol.IdentitySpendSignature())
	return input
}

func assignSpendWitness(
	input *txcircuit.Input,
	public protocol.SpendPoint,
	signature protocol.SpendSignature,
) {
	input.SpendPublic.A.X = public.X
	input.SpendPublic.A.Y = public.Y
	input.SpendSignature.R.X = signature.R.X
	input.SpendSignature.R.Y = signature.R.Y
	input.SpendSignature.S = signature.S
}

// signSpendWitnesses is the second pass: the message every input signs is the
// transaction's private hash, which only exists once every input and output
// witness is built.
func (w *inputWitnesses) signSpendWitnesses(privateTxHash *big.Int) error {
	for i, key := range w.spendKeys {
		if key == nil {
			continue
		}
		signature, err := protocol.SignSpend(*key, privateTxHash, i)
		if err != nil {
			return fmt.Errorf("input %d spend signature: %w", i, err)
		}
		assignSpendWitness(&w.inputs[i], key.Public, signature)
	}
	return nil
}

// dummyInputWitness fills an unused input slot with a random-blinded UTXO so
// the public transcript is indistinguishable from a real input. Ownership and
// inclusion are skipped in-circuit; the caller attaches the real nullifier
// non-inclusion witness (checked for every slot) and publishes the derived
// dummy nullifier. The public state root stays zero because the on-chain
// verifier treats missing root indices as zero.
func dummyInputWitness(utxo txcircuit.UtxoCircuitFields) txcircuit.Input {
	witness := newInputWitness()
	witness.Utxo = utxo
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
