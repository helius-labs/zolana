package transaction

import (
	"fmt"
	"math/big"
	"strings"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

// TransactionRequiresP256 reports whether a transaction uses the P256 ownership
// rail (any input is P256-owned) rather than the Solana-only rail. Callers use
// it to select the matching proving system / verifying key before proving.
func TransactionRequiresP256(tx ProofTransactionRequest) bool {
	for i := range tx.Inputs {
		if strings.TrimSpace(tx.Inputs[i].Utxo.OwnerP256Pubkey) != "" {
			return true
		}
	}
	return false
}

type proofBuildOptions struct {
	AllowMissingP256Signature bool
}

// assignmentTranscript holds values computed while building the witness that
// the bundle/payload need beyond the circuit: the input/output hash chains and
// nullifiers (some surface as real public outputs, see BuildProofBundle), plus
// the ownership metadata. These are production values, not debug-only.
type assignmentTranscript struct {
	inputHashes              []*big.Int
	outputHashes             []*big.Int
	nullifiers               []*big.Int
	solanaOwnerPubkeys       []string
	requiresP256OwnerWitness bool
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
	circuit         *txcircuit.Circuit
	publicInputs    protocol.PublicInputs
	publicInputHash *big.Int
	// p256MessageDigest is the full SHA-256 ECDSA message the P256 owner signs;
	// the signing payload carries it. Zero on the Solana-only rail.
	p256MessageDigest [32]byte
	outputUtxos       []ProofUtxoResponse
	transcript        assignmentTranscript
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
	external, err := buildExternalData(tx)
	if err != nil {
		return proofAssignment{}, err
	}
	// This builder constructs only real spends and padding dummies, never address
	// slots, so the address category is all zeros (one per input).
	addressHashes := make([]*big.Int, shape.NInputs)
	for i := range addressHashes {
		addressHashes[i] = big.NewInt(0)
	}
	privateTxHash, err := protocol.PrivateTxHash(inputs.hashes, outputs.privateTxHashes, addressHashes, external.hash)
	if err != nil {
		return proofAssignment{}, err
	}
	p256MessageDigest, err := protocol.P256MessageDigest(privateTxHash)
	if err != nil {
		return proofAssignment{}, err
	}
	// Ownership rail: a transaction with any P256 input uses the P256-capable
	// circuit; otherwise the Solana-only variant, which omits the P256 gadget
	// and pins both message-hash limbs to 0 (no signature). The rail must match
	// the proving system the caller selected (buildProofTransaction checks this).
	requiresP256 := inputs.requiresP256OwnerWitness
	if !requiresP256 {
		p256MessageDigest = [32]byte{}
	}
	p256MessageLow, p256MessageHigh := protocol.P256MessageLimbs(p256MessageDigest)
	p256MessageHashField, err := protocol.P256MessageHashField(p256MessageLow, p256MessageHigh)
	if err != nil {
		return proofAssignment{}, err
	}
	p256Pub, p256Sig, err := p256WitnessForTransaction(
		tx,
		p256MessageDigest,
		inputs.requiresP256OwnerWitness,
		options.AllowMissingP256Signature,
	)
	if err != nil {
		return proofAssignment{}, err
	}
	publicInputs := buildPublicInputs(payerHash, inputs, outputs, external, privateTxHash, p256MessageHashField)
	publicInputHash, err := protocol.PublicInputHash(publicInputs)
	if err != nil {
		return proofAssignment{}, err
	}

	assignment := &txcircuit.Circuit{
		Shape:                txcircuit.Shape{NInputs: shape.NInputs, NOutputs: shape.NOutputs},
		RequiresP256:         requiresP256,
		Inputs:               inputs.inputs,
		Outputs:              outputs.outputs,
		P256SigningPkField:   big.NewInt(0),
		ExternalDataHash:     external.hash,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		PrivateTxHash:        privateTxHash,
		P256MessageHashLow:   p256MessageLow,
		P256MessageHashHigh:  p256MessageHigh,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ZoneProgramID:        publicInputs.ZoneProgramID,
		PayerPubkeyHash:      publicInputs.PayerPubkeyHash,
		PublicInputHash:      publicInputHash,
	}
	transcript := assignmentTranscript{
		inputHashes:              inputs.hashes,
		outputHashes:             outputs.hashes,
		nullifiers:               inputs.nullifiers,
		solanaOwnerPubkeys:       inputs.solanaOwnerPubkeys,
		requiresP256OwnerWitness: inputs.requiresP256OwnerWitness,
	}
	return proofAssignment{
		circuit:           assignment,
		publicInputs:      publicInputs,
		publicInputHash:   publicInputHash,
		p256MessageDigest: p256MessageDigest,
		outputUtxos:       outputs.responses,
		transcript:        transcript,
	}, nil
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
	p256MessageHash *big.Int,
) protocol.PublicInputs {
	return protocol.PublicInputs{
		Nullifiers:           inputs.nullifiers,
		OutputUtxoHashes:     outputs.hashes,
		UtxoTreeRoots:        inputs.utxoRoots,
		NullifierTreeRoots:   inputs.nullifierTreeRoots,
		PrivateTxHash:        privateTxHash,
		P256MessageHash:      p256MessageHash,
		ExternalDataHash:     external.hash,
		PublicSolAmount:      external.publicSolAmount,
		PublicSplAmount:      external.publicSplAmount,
		PublicSplAssetPubkey: external.publicSplAsset,
		ZoneProgramID:        external.zoneProgramID,
		PayerPubkeyHash:      new(big.Int).Set(payerHash),
		InputOwnerPkHashes:   inputs.inputOwnerPkHashes,
	}
}
