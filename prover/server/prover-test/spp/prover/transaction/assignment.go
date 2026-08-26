package transaction

import (
	"fmt"
	"math/big"
	"strings"

	customring "zolana/prover/circuits/spp_transaction/custom"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

// TransactionRequiresP256 reports whether a transaction uses the removed P256
// ownership rail (any input is P256-owned). Such transactions can no longer be
// proven; callers should reject them.
func TransactionRequiresP256(tx ProofTransactionRequest) bool {
	for i := range tx.Inputs {
		if strings.TrimSpace(tx.Inputs[i].Utxo.OwnerP256Pubkey) != "" {
			return true
		}
	}
	return false
}

type proofBuildOptions struct {
}

// assignmentTranscript holds values computed while building the witness that
// the bundle/payload need beyond the circuit: the input/output hash chains and
// nullifiers (some surface as real public outputs, see BuildProofBundle), plus
// the ownership metadata. These are production values, not debug-only.
type assignmentTranscript struct {
	inputHashes        []*big.Int
	outputHashes       []*big.Int
	nullifiers         []*big.Int
	solanaOwnerPubkeys []string
}

type stateWitnesses struct {
	root    *big.Int
	entries map[uint64]*big.Int
	proofs  map[uint64]protocol.StateTreeWitness
}

// proofAssignment bundles everything buildProofAssignment produces: the circuit
// witness, the public inputs and their hash, the output-UTXO responses, and the
// transcript. Returning a struct keeps callers from positionally
// unpacking six values.
type proofAssignment struct {
	witness         frontend.Circuit
	publicInputs    protocol.PublicInputs
	publicInputHash *big.Int
	outputUtxos     []ProofUtxoResponse
	transcript      assignmentTranscript
}

func buildProofAssignment(
	shape protocol.Shape,
	tx ProofTransactionRequest,
	payerHash *big.Int,
	options proofBuildOptions,
) (proofAssignment, error) {
	if err := validateProofShape(shape, tx); err != nil {
		return proofAssignment{}, err
	}
	state, err := buildProofStateTree(tx.StateEntries)
	if err != nil {
		return proofAssignment{}, err
	}
	nullifierTree, err := buildProofNullifierTree(tx.NullifierEntries)
	if err != nil {
		return proofAssignment{}, err
	}
	inputs, err := buildInputWitnesses(shape, tx.Inputs, state, nullifierTree)
	if err != nil {
		return proofAssignment{}, err
	}
	outputs, err := buildOutputWitnesses(shape, tx.Outputs)
	if err != nil {
		return proofAssignment{}, err
	}
	realOutputHashes, err := instructionOutputHashes(outputs.hashes, len(tx.Outputs))
	if err != nil {
		return proofAssignment{}, err
	}
	external, err := buildExternalData(tx, realOutputHashes)
	if err != nil {
		return proofAssignment{}, err
	}
	// This builder constructs only real spends and padding dummies, never address
	// slots, so the address category is all zeros (one per input).
	addressHashes := make([]*big.Int, shape.NInputs)
	for i := range addressHashes {
		addressHashes[i] = big.NewInt(0)
	}
	privateTxBlinding := big.NewInt(0xB11D)
	privateTxHash, err := protocol.PrivateTxHash(
		inputs.hashes,
		outputs.privateTxHashes,
		addressHashes,
		external.hash,
		privateTxBlinding,
	)
	if err != nil {
		return proofAssignment{}, err
	}
	// The P256 ownership rail is removed; only Solana-owned inputs can be
	// proven.
	if inputs.requiresP256OwnerWitness {
		return proofAssignment{}, fmt.Errorf("spp: P256-owned inputs are no longer provable")
	}
	publicInputs := buildPublicInputs(payerHash, inputs, outputs, external, privateTxHash)
	publicInputHash, err := protocol.PublicInputHash(publicInputs)
	if err != nil {
		return proofAssignment{}, err
	}

	witness := customRingWitness(
		inputs,
		outputs,
		publicInputs,
		publicInputHash,
		privateTxBlinding,
	)
	transcript := assignmentTranscript{
		inputHashes:        inputs.hashes,
		outputHashes:       outputs.hashes,
		nullifiers:         inputs.nullifiers,
		solanaOwnerPubkeys: inputs.solanaOwnerPubkeys,
	}
	return proofAssignment{
		witness:         witness,
		publicInputs:    publicInputs,
		publicInputHash: publicInputHash,
		outputUtxos:     outputs.responses,
		transcript:      transcript,
	}, nil
}

// instructionOutputHashes selects exactly the hashes represented by
// TransactIxData.outputs. Circuit-only dummy padding is not serialized into the
// instruction and therefore must not enter the canonical ExternalDataHash.
func instructionOutputHashes(outputHashes []*big.Int, realOutputCount int) ([]*big.Int, error) {
	if realOutputCount < 0 || realOutputCount > len(outputHashes) {
		return nil, fmt.Errorf(
			"real output count %d exceeds derived output hash count %d",
			realOutputCount,
			len(outputHashes),
		)
	}
	return outputHashes[:realOutputCount:realOutputCount], nil
}

// customRingWitness materializes the rail-specific circuit assignment. This
// package proves only the custom-ring variants; the Public struct is filled
// straight from the host-computed protocol.PublicInputs.
func customRingWitness(
	inputs inputWitnesses,
	outputs outputWitnesses,
	publicInputs protocol.PublicInputs,
	publicInputHash *big.Int,
	privateTxBlinding *big.Int,
) frontend.Circuit {
	var publicAssets, publicAmounts [txcircuit.NPublicSlots]frontend.Variable
	for i := 0; i < txcircuit.NPublicSlots; i++ {
		publicAssets[i] = publicInputs.PublicAssets[i]
		publicAmounts[i] = publicInputs.PublicAmounts[i]
	}
	return &customring.CustomRingEddsaOnlyCircuit{
		Public: customring.CustomRingEddsaOnlyPublic{
			Nullifiers:                   fieldVariables(publicInputs.Nullifiers),
			OutputHashes:                 fieldVariables(publicInputs.OutputUtxoHashes),
			UtxoTreeRoots:                fieldVariables(publicInputs.UtxoTreeRoots),
			NullifierTreeRoots:           fieldVariables(publicInputs.NullifierTreeRoots),
			PrivateTxHash:                publicInputs.PrivateTxHash,
			ExternalDataHash:             publicInputs.ExternalDataHash,
			PublicAssets:                 publicAssets,
			PublicAmounts:                publicAmounts,
			RingProgramID:                publicInputs.RingProgramID,
			AllowDummyInputs:             publicInputs.AllowDummyInputs,
			SignerPkHashes:               fieldVariables(publicInputs.SignerPkHashes),
			PublishedOutputOwnerPkHashes: fieldVariables(publicInputs.OutputOwnerPkHashes),
			PublicInputHash:              publicInputHash,
		},
		Private: customring.CustomRingEddsaOnlyPrivate{
			Inputs:              inputs.inputs,
			InputOwnerPkHashes:  fieldVariables(inputs.inputOwnerPkHashes),
			Outputs:             outputs.outputs,
			OutputOwnerPkHashes: fieldVariables(outputs.outputOwnerPkHashes),
			OutputNullifierPks:  fieldVariables(outputs.outputNullifierPks),
			PrivateTxBlinding:   privateTxBlinding,
		},
	}
}

func fieldVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func validateProofShape(shape protocol.Shape, tx ProofTransactionRequest) error {
	if err := shape.Validate(); err != nil {
		return err
	}
	// Fewer real inputs/outputs than the shape are padded with dummy slots, so a
	// shape serves any transaction up to its capacity (and a shield with 0
	// inputs or an unshield with 0 outputs becomes provable).
	if len(tx.Inputs) > shape.NInputs {
		return fmt.Errorf("shape %s allows at most %d inputs, got %d", shape, shape.NInputs, len(tx.Inputs))
	}
	if len(tx.Outputs) > shape.NOutputs {
		return fmt.Errorf("shape %s allows at most %d outputs, got %d", shape, shape.NOutputs, len(tx.Outputs))
	}
	// SPP derives the verifying key and public-input padding from the real
	// counts with the smallest-fit rule, so a locally valid proof built with any
	// other (merely large-enough) shape would be rejected on-chain.
	canonical, err := protocol.CanonicalShape(len(tx.Inputs), len(tx.Outputs))
	if err != nil {
		return err
	}
	if shape != canonical {
		return fmt.Errorf(
			"shape %s is not canonical for %d inputs / %d outputs: SPP verifies with shape %s",
			shape, len(tx.Inputs), len(tx.Outputs), canonical,
		)
	}
	return nil
}

func buildProofStateTree(entries []ProofStateEntry) (stateWitnesses, error) {
	stateEntries := make(map[uint64]*big.Int, len(entries))
	for _, entry := range entries {
		hash, err := parse.Field(entry.Hash)
		if err != nil {
			return stateWitnesses{}, fmt.Errorf("state leaf %d: %w", entry.Index, err)
		}
		if _, exists := stateEntries[entry.Index]; exists {
			return stateWitnesses{}, fmt.Errorf("duplicate state leaf %d", entry.Index)
		}
		stateEntries[entry.Index] = hash
	}
	root, proofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		return stateWitnesses{}, fmt.Errorf("state tree: %w", err)
	}
	return stateWitnesses{root: root, entries: stateEntries, proofs: proofs}, nil
}

func buildProofNullifierTree(entries []string) (*protocol.NullifierTree, error) {
	tree, err := protocol.NewNullifierTree()
	if err != nil {
		return nil, fmt.Errorf("nullifier tree: %w", err)
	}
	for i, entry := range entries {
		value, err := parse.Field(entry)
		if err != nil {
			return nil, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
		if err := tree.Insert(value); err != nil {
			return nil, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
	}
	return tree, nil
}

func buildPublicInputs(
	payerHash *big.Int,
	inputs inputWitnesses,
	outputs outputWitnesses,
	external externalValues,
	privateTxHash *big.Int,
) protocol.PublicInputs {
	// Padding must reuse an owner identity already bound to real transaction
	// content.
	var participantTag *big.Int
	for _, ownerPkHash := range inputs.inputOwnerPkHashes {
		if ownerPkHash != nil && ownerPkHash.Sign() != 0 {
			participantTag = ownerPkHash
			break
		}
	}
	if participantTag == nil {
		for _, ownerPkHash := range outputs.outputOwnerPkHashes {
			if ownerPkHash != nil && ownerPkHash.Sign() != 0 {
				participantTag = ownerPkHash
				break
			}
		}
	}
	for i, ownerPkHash := range outputs.outputOwnerPkHashes {
		if participantTag != nil && (ownerPkHash == nil || ownerPkHash.Sign() == 0) {
			outputs.outputOwnerPkHashes[i] = new(big.Int).Set(participantTag)
		}
	}
	return protocol.PublicInputs{
		Nullifiers:          inputs.nullifiers,
		OutputUtxoHashes:    outputs.hashes,
		UtxoTreeRoots:       inputs.utxoRoots,
		NullifierTreeRoots:  inputs.nullifierTreeRoots,
		PrivateTxHash:       privateTxHash,
		ExternalDataHash:    external.hash,
		PublicAssets:        external.publicSlots.assets,
		PublicAmounts:       external.publicSlots.amounts,
		RingProgramID:       external.ringProgramID,
		AllowDummyInputs:    big.NewInt(1),
		SignerPkHashes:      signerPkHashes(payerHash, inputs.inputOwnerPkHashes),
		BindOutputOwnerTags: true,
		OutputOwnerPkHashes: outputs.outputOwnerPkHashes,
	}
}

func signerPkHashes(payerHash *big.Int, inputOwnerPkHashes []*big.Int) []*big.Int {
	out := make([]*big.Int, len(inputOwnerPkHashes)+1)
	out[0] = new(big.Int).Set(payerHash)
	seen := []*big.Int{payerHash}
	next := 1
	for _, owner := range inputOwnerPkHashes {
		if owner == nil || owner.Sign() == 0 {
			continue
		}
		duplicate := false
		for _, existing := range seen {
			if existing.Cmp(owner) == 0 {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seen = append(seen, owner)
		out[next] = new(big.Int).Set(owner)
		next++
	}
	for i := next; i < len(out); i++ {
		out[i] = big.NewInt(0)
	}
	return out
}
