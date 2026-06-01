package spp

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// proofAssignment is the result of building a circuit assignment for one
// transaction: the witness to prove, the public inputs it commits to, the
// normalized output UTXOs to return, and the values derived along the way that
// the response and optional debug block draw from.
type proofAssignment struct {
	circuit      *Circuit
	publicInputs PublicInputs
	outputUtxos  []ProofUtxoResponse
	external     externalData
	derived      proofDerivedValues
}

func buildProofAssignment(shape Shape, tx ProofTransactionRequest, signerHash *big.Int, options proofBuildOptions) (proofAssignment, error) {
	if len(tx.Inputs) > shape.NInputs || len(tx.Outputs) > shape.NOutputs {
		return proofAssignment{}, fmt.Errorf("shape %s cannot carry %d inputs and %d outputs", shape, len(tx.Inputs), len(tx.Outputs))
	}

	trees, err := buildProofTrees(tx)
	if err != nil {
		return proofAssignment{}, err
	}
	in, err := buildInputs(shape, tx, trees)
	if err != nil {
		return proofAssignment{}, err
	}
	out, err := buildOutputs(shape, tx)
	if err != nil {
		return proofAssignment{}, err
	}

	expiry := new(big.Int).SetUint64(tx.ExpiryUnixTs)
	external, err := buildExternalData(tx)
	if err != nil {
		return proofAssignment{}, err
	}
	externalDataHash := external.hash
	privateTxHash, err := PrivateTxHash(in.hashes, out.hashes, externalDataHash, expiry)
	if err != nil {
		return proofAssignment{}, err
	}
	p256Pub, p256Sig, err := p256WitnessForTransaction(tx, privateTxHash, in.requiresP256, options.AllowMissingP256Signature)
	if err != nil {
		return proofAssignment{}, err
	}
	amounts, err := derivePublicAmounts(tx)
	if err != nil {
		return proofAssignment{}, err
	}
	programIDHashChain, err := optionalField(tx.ProgramIDHashChain)
	if err != nil {
		return proofAssignment{}, fmt.Errorf("program_id_hashchain: %w", err)
	}
	publicInputs := PublicInputs{
		Nullifiers:           in.nullifiers,
		OutputUtxoHashes:     out.hashes,
		UtxoTreeRoots:        in.utxoRoots,
		NullifierRoots:       in.nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		PublicSolAmount:      amounts.sol,
		PublicSplAmount:      amounts.spl,
		PublicSplAssetPubkey: amounts.asset,
		ProgramIDHashChain:   programIDHashChain,
		SolanaPubkeyHash:     new(big.Int).Set(signerHash),
		SolanaPkHashes:       in.solanaPkHashes,
	}
	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return proofAssignment{}, err
	}

	circuit := &Circuit{
		Shape:                shape,
		Inputs:               in.inputs,
		Outputs:              out.outputs,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		NullifierSecret:      in.sharedNullifierSecret,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		PrivateTxHash:        privateTxHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashChain:   publicInputs.ProgramIDHashChain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		PublicInputHash:      publicInputHash,
	}
	return proofAssignment{
		circuit:      circuit,
		publicInputs: publicInputs,
		outputUtxos:  out.responses,
		external:     external,
		derived: proofDerivedValues{
			inputHashes:              in.hashes,
			outputHashes:             out.hashes,
			nullifiers:               in.nullifiers,
			inUtxoSignerIndices:      in.signerIndices,
			requiresP256OwnerWitness: in.requiresP256,
		},
	}, nil
}

// proofTrees holds the sparse state tree and indexed nullifier tree built from a
// transaction's declared entries, along with the membership proofs the input
// witnesses draw from.
type proofTrees struct {
	stateEntries  map[uint64]*big.Int
	stateRoot     *big.Int
	stateProofs   map[uint64]StateTreeWitness
	nullifierTree *IndexedTree
}

func buildProofTrees(tx ProofTransactionRequest) (proofTrees, error) {
	stateEntries := make(map[uint64]*big.Int, len(tx.StateEntries))
	maxStateIndex := uint64(1) << StateTreeHeight
	for _, entry := range tx.StateEntries {
		if entry.Index >= maxStateIndex {
			return proofTrees{}, fmt.Errorf("state leaf index %d out of range for tree height %d", entry.Index, StateTreeHeight)
		}
		if _, dup := stateEntries[entry.Index]; dup {
			return proofTrees{}, fmt.Errorf("duplicate state leaf index %d", entry.Index)
		}
		hash, err := parseField(entry.Hash)
		if err != nil {
			return proofTrees{}, fmt.Errorf("state leaf %d: %w", entry.Index, err)
		}
		stateEntries[entry.Index] = hash
	}
	stateRoot, stateProofs := BuildSparseStateTree(stateEntries)
	nullifierTree := NewIndexedTree()
	for i, entry := range tx.NullifierEntries {
		value, err := parseField(entry)
		if err != nil {
			return proofTrees{}, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
		if err := nullifierTree.InsertChecked(value); err != nil {
			return proofTrees{}, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
	}
	return proofTrees{
		stateEntries:  stateEntries,
		stateRoot:     stateRoot,
		stateProofs:   stateProofs,
		nullifierTree: nullifierTree,
	}, nil
}

// builtInputs is the input half of a circuit assignment: the per-slot Input
// witnesses plus the derived values the public inputs and response draw from.
// Dummy slots (index >= len(tx.Inputs)) carry zero values.
type builtInputs struct {
	inputs                []Input
	hashes                []*big.Int
	nullifiers            []*big.Int
	utxoRoots             []*big.Int
	nullifierRoots        []*big.Int
	solanaPkHashes        []*big.Int
	sharedNullifierSecret *big.Int
	requiresP256          bool
	signerIndices         []int
}

func buildInputs(shape Shape, tx ProofTransactionRequest, trees proofTrees) (builtInputs, error) {
	b := builtInputs{
		inputs:                make([]Input, shape.NInputs),
		hashes:                make([]*big.Int, shape.NInputs),
		nullifiers:            make([]*big.Int, shape.NInputs),
		utxoRoots:             make([]*big.Int, shape.NInputs),
		nullifierRoots:        make([]*big.Int, shape.NInputs),
		solanaPkHashes:        make([]*big.Int, shape.NInputs),
		sharedNullifierSecret: big.NewInt(0),
		signerIndices:         make([]int, 0, len(tx.Inputs)),
	}
	for i := 0; i < shape.NInputs; i++ {
		statePath := proofZeroVariableSlice(StateTreeHeight)
		stateDirs := proofZeroVariableSlice(StateTreeHeight)
		nfLowPath := proofZeroVariableSlice(NullifierTreeHeight)
		nfLowDirs := proofZeroVariableSlice(NullifierTreeHeight)
		nfLowValue := big.NewInt(0)
		nfNextValue := big.NewInt(0)

		if i >= len(tx.Inputs) {
			b.hashes[i] = big.NewInt(0)
			b.nullifiers[i] = big.NewInt(0)
			b.utxoRoots[i] = big.NewInt(0)
			b.nullifierRoots[i] = big.NewInt(0)
			b.solanaPkHashes[i] = big.NewInt(0)
			b.inputs[i] = Input{
				Utxo:          toProofCircuitFields(proofZeroUtxo()),
				IsDummy:       frontend.Variable(1),
				NullifierPk:   big.NewInt(0),
				SolanaPkHash:  big.NewInt(0),
				Nullifier:     big.NewInt(0),
				UtxoTreeRoot:  big.NewInt(0),
				NullifierRoot: big.NewInt(0),
				State:         MerkleProof{Siblings: statePath, Directions: stateDirs},
				NfLowValue:    nfLowValue,
				NfNextValue:   nfNextValue,
				NfLow:         MerkleProof{Siblings: nfLowPath, Directions: nfLowDirs},
			}
			continue
		}

		input, err := parseProofInput(tx.Inputs[i])
		if err != nil {
			return builtInputs{}, fmt.Errorf("input %d: %w", i, err)
		}
		if i == 0 {
			b.sharedNullifierSecret = input.nullifierSecret
		} else if b.sharedNullifierSecret.Cmp(input.nullifierSecret) != 0 {
			return builtInputs{}, fmt.Errorf("input %d nullifier_secret differs from input 0", i)
		}
		inputHash, err := UtxoHash(input.utxo)
		if err != nil {
			return builtInputs{}, err
		}
		if existing, ok := trees.stateEntries[input.leafIndex]; !ok || existing.Cmp(inputHash) != 0 {
			return builtInputs{}, fmt.Errorf("input %d leaf %d is not present in state_entries", i, input.leafIndex)
		}
		nullifier, err := NullifierHash(inputHash, input.utxo.Blinding, input.nullifierSecret)
		if err != nil {
			return builtInputs{}, err
		}
		proof, ok := trees.stateProofs[input.leafIndex]
		if !ok {
			return builtInputs{}, fmt.Errorf("missing state proof for leaf %d", input.leafIndex)
		}
		fillProofPath(statePath, stateDirs, proof.Siblings, proof.Directions)

		nfWitness := trees.nullifierTree.NonInclusion(nullifier)
		nfLowValue = nfWitness.LowValue
		nfNextValue = nfWitness.NextValue
		fillProofPath(nfLowPath, nfLowDirs, nfWitness.Siblings, nfWitness.Directions)

		solanaPkHash := big.NewInt(0)
		if input.isP256 {
			b.requiresP256 = true
		} else {
			solanaPkHash = input.ownerKeyHash
			b.signerIndices = append(b.signerIndices, i)
		}

		b.hashes[i] = inputHash
		b.nullifiers[i] = nullifier
		b.utxoRoots[i] = trees.stateRoot
		b.nullifierRoots[i] = trees.nullifierTree.Root
		b.solanaPkHashes[i] = solanaPkHash
		b.inputs[i] = Input{
			Utxo:          toProofCircuitFields(input.utxo),
			IsDummy:       frontend.Variable(0),
			NullifierPk:   input.nullifierPk,
			SolanaPkHash:  solanaPkHash,
			Nullifier:     nullifier,
			UtxoTreeRoot:  trees.stateRoot,
			NullifierRoot: trees.nullifierTree.Root,
			State:         MerkleProof{Siblings: statePath, Directions: stateDirs},
			NfLowValue:    nfLowValue,
			NfNextValue:   nfNextValue,
			NfLow:         MerkleProof{Siblings: nfLowPath, Directions: nfLowDirs},
		}
	}
	return b, nil
}

// builtOutputs is the output half of a circuit assignment: the per-slot Output
// witnesses, their hashes (for the private-tx hash and public inputs), and the
// normalized UTXO responses returned to the caller.
type builtOutputs struct {
	outputs   []Output
	hashes    []*big.Int
	responses []ProofUtxoResponse
}

func buildOutputs(shape Shape, tx ProofTransactionRequest) (builtOutputs, error) {
	b := builtOutputs{
		outputs:   make([]Output, shape.NOutputs),
		hashes:    make([]*big.Int, shape.NOutputs),
		responses: make([]ProofUtxoResponse, 0, len(tx.Outputs)),
	}
	for i := 0; i < shape.NOutputs; i++ {
		if i >= len(tx.Outputs) {
			b.hashes[i] = big.NewInt(0)
			b.outputs[i] = Output{
				Utxo:    toProofCircuitFields(proofZeroUtxo()),
				IsDummy: frontend.Variable(1),
				Hash:    big.NewInt(0),
			}
			continue
		}
		parsed, err := parseProofUtxo(tx.Outputs[i], nil)
		if err != nil {
			return builtOutputs{}, fmt.Errorf("output %d: %w", i, err)
		}
		outputHash, err := UtxoHash(parsed.utxo)
		if err != nil {
			return builtOutputs{}, err
		}
		b.hashes[i] = outputHash
		b.outputs[i] = Output{
			Utxo:    toProofCircuitFields(parsed.utxo),
			IsDummy: frontend.Variable(0),
			Hash:    outputHash,
		}
		b.responses = append(b.responses, ProofUtxoResponse{
			Utxo: parsed.normalized,
			Hash: proofFieldHex(outputHash),
		})
	}
	return b, nil
}
