package transaction

import (
	"fmt"
	"math/big"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

type proofBuildOptions struct {
	AllowMissingP256Signature bool
}

type assignmentDebug struct {
	inputHashes              []*big.Int
	outputHashes             []*big.Int
	nullifiers               []*big.Int
	solanaOwnerInputIndices  []int
	requiresP256OwnerWitness bool
}

type stateWitnesses struct {
	root    *big.Int
	entries map[uint64]*big.Int
	proofs  map[uint64]protocol.StateTreeWitness
}

func buildProofAssignment(
	shape protocol.Shape,
	tx ProofTransactionRequest,
	signerHash *big.Int,
	options proofBuildOptions,
) (*txcircuit.Circuit, protocol.PublicInputs, *big.Int, []ProofUtxoResponse, assignmentDebug, error) {
	if err := validateProofShape(shape, tx); err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	state, err := buildProofStateTree(tx.StateEntries)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	nullifierTree, err := buildProofNullifierTree(tx.NullifierEntries)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	inputs, err := buildInputWitnesses(shape, tx.Inputs, state, nullifierTree)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	outputs, err := buildOutputWitnesses(shape, tx.Outputs)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	external, err := buildExternalData(tx)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	privateTxHash, err := protocol.PrivateTxHash(inputs.hashes, outputs.hashes, external.hash, external.expiry)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	p256MessageHash, err := protocol.P256MessageHash(privateTxHash)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	p256Pub, p256Sig, err := p256WitnessForTransaction(
		tx,
		p256MessageHash,
		inputs.requiresP256OwnerWitness,
		options.AllowMissingP256Signature,
	)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}
	publicInputs := buildPublicInputs(signerHash, inputs, outputs, external, privateTxHash, p256MessageHash)
	publicInputHash, err := protocol.PublicInputHash(publicInputs)
	if err != nil {
		return nil, protocol.PublicInputs{}, nil, nil, assignmentDebug{}, err
	}

	assignment := &txcircuit.Circuit{
		Shape:                shape,
		Inputs:               inputs.inputs,
		Outputs:              outputs.outputs,
		ExternalDataHash:     external.hash,
		ExpiryUnixTs:         external.expiry,
		NullifierSecret:      inputs.nullifierSecret,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		PrivateTxHash:        privateTxHash,
		P256MessageHash:      p256MessageHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashchain:   publicInputs.ProgramIDHashchain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		DataHash:             publicInputs.DataHash,
		ZoneDataHash:         publicInputs.ZoneDataHash,
		PublicInputHash:      publicInputHash,
	}
	debug := assignmentDebug{
		inputHashes:              inputs.hashes,
		outputHashes:             outputs.hashes,
		nullifiers:               inputs.nullifiers,
		solanaOwnerInputIndices:  inputs.solanaOwnerInputIndices,
		requiresP256OwnerWitness: inputs.requiresP256OwnerWitness,
	}
	return assignment, publicInputs, publicInputHash, outputs.responses, debug, nil
}

func validateProofShape(shape protocol.Shape, tx ProofTransactionRequest) error {
	if err := shape.Validate(); err != nil {
		return err
	}
	if len(tx.Inputs) != shape.NInputs {
		return fmt.Errorf("shape %s requires %d inputs, got %d", shape, shape.NInputs, len(tx.Inputs))
	}
	if len(tx.Outputs) != shape.NOutputs {
		return fmt.Errorf("shape %s requires %d outputs, got %d", shape, shape.NOutputs, len(tx.Outputs))
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
	signerHash *big.Int,
	inputs inputWitnesses,
	outputs outputWitnesses,
	external externalValues,
	privateTxHash *big.Int,
	p256MessageHash *big.Int,
) protocol.PublicInputs {
	return protocol.PublicInputs{
		Nullifiers:           inputs.nullifiers,
		OutputUtxoHashes:     outputs.hashes,
		UtxoTreeRoots:        inputs.utxoRoots,
		NullifierRoots:       inputs.nullifierRoots,
		PrivateTxHash:        privateTxHash,
		P256MessageHash:      p256MessageHash,
		ExternalDataHash:     external.hash,
		PublicSolAmount:      external.publicSolAmount,
		PublicSplAmount:      external.publicSplAmount,
		PublicSplAssetPubkey: external.publicSplAsset,
		ProgramIDHashchain:   external.programIDHashchain,
		SolanaPubkeyHash:     new(big.Int).Set(signerHash),
		SolanaPkHashes:       inputs.solanaPkHashes,
		DataHash:             external.dataHash,
		ZoneDataHash:         external.zoneDataHash,
	}
}
