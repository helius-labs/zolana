package spp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"light/light-prover/prover/common"

	"github.com/consensys/gnark/frontend"
)

func WriteProofBundle(ps *ProofSystem, requestPath string, outputPath string) error {
	bytes, err := os.ReadFile(requestPath)
	if err != nil {
		return err
	}
	var request ProofBundleRequest
	if err := json.Unmarshal(bytes, &request); err != nil {
		return err
	}
	bundle, err := BuildProofBundle(ps, request)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(outputPath, out, 0644)
}

func WriteProofSigningPayload(ps *ProofSystem, requestPath string, outputPath string) error {
	bytes, err := os.ReadFile(requestPath)
	if err != nil {
		return err
	}
	var request ProofBundleRequest
	if err := json.Unmarshal(bytes, &request); err != nil {
		return err
	}
	bundle, err := BuildProofSigningPayload(ps, request)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(outputPath, out, 0644)
}

func BuildProofBundle(ps *ProofSystem, request ProofBundleRequest) (*ProofBundle, error) {
	if err := ps.Shape.Validate(); err != nil {
		return nil, err
	}
	signerPubkey, err := parseHex32(request.SolanaSignerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: signer pubkey: %w", err)
	}
	signerHash := HashToFieldSize(signerPubkey[:])
	out := &ProofBundle{
		Shape:                 ps.Shape,
		SolanaSignerPubkeyHex: proofBytesHex(signerPubkey[:]),
	}
	for _, tx := range request.Transactions {
		proved, err := buildProofTransaction(ps, tx, signerHash)
		if err != nil {
			return nil, fmt.Errorf("spp: transaction %q: %w", tx.Name, err)
		}
		out.Transactions = append(out.Transactions, proved)
	}
	return out, nil
}

func BuildProofSigningPayload(ps *ProofSystem, request ProofBundleRequest) (*ProofSigningPayloadBundle, error) {
	if err := ps.Shape.Validate(); err != nil {
		return nil, err
	}
	signerPubkey, err := parseHex32(request.SolanaSignerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: signer pubkey: %w", err)
	}
	signerHash := HashToFieldSize(signerPubkey[:])
	out := &ProofSigningPayloadBundle{
		Shape:                 ps.Shape,
		SolanaSignerPubkeyHex: proofBytesHex(signerPubkey[:]),
	}
	for _, tx := range request.Transactions {
		payload, err := buildProofSigningPayloadTransaction(ps.Shape, tx, signerHash)
		if err != nil {
			return nil, fmt.Errorf("spp: transaction %q: %w", tx.Name, err)
		}
		out.Transactions = append(out.Transactions, payload)
	}
	return out, nil
}

func buildProofTransaction(ps *ProofSystem, tx ProofTransactionRequest, signerHash *big.Int) (ProofTransaction, error) {
	assignment, publicInputs, outputUtxos, debug, err := buildProofAssignment(ps.Shape, tx, signerHash, proofBuildOptions{})
	if err != nil {
		return ProofTransaction{}, err
	}
	proof, err := Prove(ps, assignment)
	if err != nil {
		return ProofTransaction{}, err
	}
	if err := Verify(ps, assignment, proof); err != nil {
		return ProofTransaction{}, err
	}
	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return ProofTransaction{}, err
	}

	utxoRootIndices, err := proofRootIndices(tx.UtxoTreeRootIndex, len(tx.Inputs), "utxo_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}
	nullifierRootIndices, err := proofRootIndices(tx.NullifierTreeRootIndex, len(tx.Inputs), "nullifier_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}
	userSolAccount, err := parseOptionalHex32(tx.UserSolAccount)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("user_sol_account: %w", err)
	}
	userSplTokenAccount, err := parseOptionalHex32(tx.UserSplTokenAccount)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("user_spl_token_account: %w", err)
	}
	splTokenInterface, err := parseOptionalHex32(tx.SplTokenInterface)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("spl_token_interface: %w", err)
	}

	return ProofTransaction{
		Name:                   tx.Name,
		ExpiryUnixTs:           tx.ExpiryUnixTs,
		SenderViewTag:          strings.TrimPrefix(tx.SenderViewTag, "0x"),
		Proof:                  &common.Proof{Proof: proof},
		RelayerFee:             tx.RelayerFee,
		Nullifiers:             proofTrimTrailingZeroHexes(debug.nullifiers),
		OutputUtxoHashes:       proofTrimTrailingZeroHexes(debug.outputHashes),
		UtxoTreeRootIndex:      utxoRootIndices,
		NullifierTreeRootIndex: nullifierRootIndices,
		PrivateTxHash:          proofFieldHex(publicInputs.PrivateTxHash),
		PublicAmountMode:       tx.PublicAmountMode,
		PublicSolAmount:        tx.PublicSolAmount,
		PublicSplAmount:        tx.PublicSplAmount,
		PublicSplAssetPubkey:   strings.TrimPrefix(tx.PublicSplAssetPubkey, "0x"),
		EncryptedUtxos:         strings.TrimPrefix(tx.EncryptedUtxos, "0x"),
		PublicInputHash:        proofFieldHex(publicInputHash),
		ExternalDataHash:       proofFieldHex(publicInputs.ExternalDataHash),
		UserSolAccount:         proofBytesHex(userSolAccount[:]),
		UserSplTokenAccount:    proofBytesHex(userSplTokenAccount[:]),
		SplTokenInterface:      proofBytesHex(splTokenInterface[:]),
		InUtxoSignerIndices:    debug.inUtxoSignerIndices,
		OutputUtxos:            outputUtxos,
		Debug: &ProofDebug{
			InputUtxoHashes:    proofBigIntHexes(debug.inputHashes),
			OutputUtxoHashes:   proofBigIntHexes(debug.outputHashes),
			UtxoTreeRoots:      proofBigIntHexes(publicInputs.UtxoTreeRoots),
			NullifierTreeRoots: proofBigIntHexes(publicInputs.NullifierRoots),
		},
	}, nil
}

func buildProofSigningPayloadTransaction(shape Shape, tx ProofTransactionRequest, signerHash *big.Int) (ProofSigningPayloadTransaction, error) {
	_, publicInputs, _, debug, err := buildProofAssignment(shape, tx, signerHash, proofBuildOptions{
		AllowMissingP256Signature: true,
	})
	if err != nil {
		return ProofSigningPayloadTransaction{}, err
	}
	return ProofSigningPayloadTransaction{
		Name:                  tx.Name,
		PrivateTxHash:         proofFieldHex(publicInputs.PrivateTxHash),
		RequiresP256Signature: debug.requiresP256OwnerWitness,
	}, nil
}

type proofBuildOptions struct {
	AllowMissingP256Signature bool
}

func proofRootIndices(indices []uint16, inputCount int, name string) ([]uint16, error) {
	if len(indices) == 0 {
		return make([]uint16, inputCount), nil
	}
	if len(indices) != inputCount {
		return nil, fmt.Errorf("spp: %s length %d does not match input count %d", name, len(indices), inputCount)
	}
	out := make([]uint16, inputCount)
	copy(out, indices)
	return out, nil
}

func buildProofAssignment(shape Shape, tx ProofTransactionRequest, signerHash *big.Int, options proofBuildOptions) (*Circuit, PublicInputs, []ProofUtxoResponse, proofDebug, error) {
	if len(tx.Inputs) > shape.NInputs || len(tx.Outputs) > shape.NOutputs {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("shape %s cannot carry %d inputs and %d outputs", shape, len(tx.Inputs), len(tx.Outputs))
	}

	stateEntries := make(map[uint64]*big.Int, len(tx.StateEntries))
	for _, entry := range tx.StateEntries {
		hash, err := parseField(entry.Hash)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("state leaf %d: %w", entry.Index, err)
		}
		stateEntries[entry.Index] = hash
	}
	stateRoot, stateProofs := BuildSparseStateTree(stateEntries)
	nullifierTree := NewIndexedTree()
	for i, entry := range tx.NullifierEntries {
		value, err := parseField(entry)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
		if err := nullifierTree.InsertChecked(value); err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("nullifier_entries[%d]: %w", i, err)
		}
	}

	inputUtxos := make([]UtxoCircuitFields, shape.NInputs)
	inputNullifierPk := make([]frontend.Variable, shape.NInputs)
	solanaPkHashes := make([]frontend.Variable, shape.NInputs)
	isDummyInput := make([]frontend.Variable, shape.NInputs)
	statePath := make([][]frontend.Variable, shape.NInputs)
	stateDirs := make([][]frontend.Variable, shape.NInputs)
	nfLowValue := make([]frontend.Variable, shape.NInputs)
	nfNextValue := make([]frontend.Variable, shape.NInputs)
	nfLowPath := make([][]frontend.Variable, shape.NInputs)
	nfLowDirs := make([][]frontend.Variable, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	utxoRoots := make([]*big.Int, shape.NInputs)
	nullifierRoots := make([]*big.Int, shape.NInputs)
	sharedNullifierSecret := big.NewInt(0)
	requiresP256 := false
	inUtxoSignerIndices := make([]int, 0, len(tx.Inputs))

	for i := 0; i < shape.NInputs; i++ {
		statePath[i] = proofZeroVariableSlice(StateTreeHeight)
		stateDirs[i] = proofZeroVariableSlice(StateTreeHeight)
		nfLowPath[i] = proofZeroVariableSlice(NullifierTreeHeight)
		nfLowDirs[i] = proofZeroVariableSlice(NullifierTreeHeight)
		nfLowValue[i] = big.NewInt(0)
		nfNextValue[i] = big.NewInt(0)
		utxoRoots[i] = big.NewInt(0)
		nullifierRoots[i] = big.NewInt(0)

		if i >= len(tx.Inputs) {
			inputUtxos[i] = toProofCircuitFields(proofZeroUtxo())
			inputNullifierPk[i] = big.NewInt(0)
			solanaPkHashes[i] = big.NewInt(0)
			isDummyInput[i] = frontend.Variable(1)
			nullifiers[i] = big.NewInt(0)
			inputHashes[i] = big.NewInt(0)
			continue
		}

		input, err := parseProofInput(tx.Inputs[i])
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("input %d: %w", i, err)
		}
		if i == 0 {
			sharedNullifierSecret = input.nullifierSecret
		} else if sharedNullifierSecret.Cmp(input.nullifierSecret) != 0 {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("input %d nullifier_secret differs from input 0", i)
		}
		inputHash, err := UtxoHash(input.utxo)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, err
		}
		if existing, ok := stateEntries[input.leafIndex]; !ok || existing.Cmp(inputHash) != 0 {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("input %d leaf %d is not present in state_entries", i, input.leafIndex)
		}
		nullifier, err := NullifierHash(inputHash, input.utxo.Blinding, input.nullifierSecret)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, err
		}
		inputUtxos[i] = toProofCircuitFields(input.utxo)
		inputHashes[i] = inputHash
		inputNullifierPk[i] = input.nullifierPk
		if input.isP256 {
			solanaPkHashes[i] = big.NewInt(0)
			requiresP256 = true
		} else {
			solanaPkHashes[i] = input.ownerKeyHash
			inUtxoSignerIndices = append(inUtxoSignerIndices, i)
		}
		isDummyInput[i] = frontend.Variable(0)
		nullifiers[i] = nullifier
		utxoRoots[i] = stateRoot
		nullifierRoots[i] = nullifierTree.Root

		proof, ok := stateProofs[input.leafIndex]
		if !ok {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("missing state proof for leaf %d", input.leafIndex)
		}
		fillProofPath(statePath[i], stateDirs[i], proof.Siblings, proof.Directions)

		nfWitness := nullifierTree.NonInclusion(nullifier)
		nfLowValue[i] = nfWitness.LowValue
		nfNextValue[i] = nfWitness.NextValue
		fillProofPath(nfLowPath[i], nfLowDirs[i], nfWitness.Siblings, nfWitness.Directions)
	}

	outputUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	isDummyOutput := make([]frontend.Variable, shape.NOutputs)
	outputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVars := make([]frontend.Variable, shape.NOutputs)
	outputResponses := make([]ProofUtxoResponse, 0, len(tx.Outputs))
	for i := 0; i < shape.NOutputs; i++ {
		if i >= len(tx.Outputs) {
			outputUtxos[i] = toProofCircuitFields(proofZeroUtxo())
			isDummyOutput[i] = frontend.Variable(1)
			outputHashes[i] = big.NewInt(0)
			outputHashVars[i] = big.NewInt(0)
			continue
		}
		parsed, err := parseProofUtxo(tx.Outputs[i], nil)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("output %d: %w", i, err)
		}
		outputHash, err := UtxoHash(parsed.utxo)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, err
		}
		outputUtxos[i] = toProofCircuitFields(parsed.utxo)
		isDummyOutput[i] = frontend.Variable(0)
		outputHashes[i] = outputHash
		outputHashVars[i] = outputHash
		outputResponses = append(outputResponses, ProofUtxoResponse{
			Utxo: parsed.normalized,
			Hash: proofFieldHex(outputHash),
		})
	}

	senderViewTag, err := parseField(tx.SenderViewTag)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("sender_view_tag: %w", err)
	}
	expiry := new(big.Int).SetUint64(tx.ExpiryUnixTs)
	encryptedUtxos, err := parseHexBytes(tx.EncryptedUtxos)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("encrypted_utxos: %w", err)
	}
	userSolAccount, err := parseOptionalHex32(tx.UserSolAccount)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("user_sol_account: %w", err)
	}
	userSplTokenAccount, err := parseOptionalHex32(tx.UserSplTokenAccount)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("user_spl_token_account: %w", err)
	}
	splTokenInterface, err := parseOptionalHex32(tx.SplTokenInterface)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("spl_token_interface: %w", err)
	}
	externalDataHash := proofExternalDataFieldHash(proofExternalData{
		InstructionDiscriminator: tx.InstructionDiscriminator,
		ExpiryUnixTs:             tx.ExpiryUnixTs,
		SenderViewTag:            proofFieldBytes(senderViewTag),
		RelayerFee:               tx.RelayerFee,
		PublicSolAmount:          optionalU64(tx.PublicSolAmount),
		PublicSplAmount:          optionalU64(tx.PublicSplAmount),
		UserSolAccount:           userSolAccount,
		UserSplToken:             userSplTokenAccount,
		SplTokenInterface:        splTokenInterface,
		EncryptedUtxos:           encryptedUtxos,
	})
	privateTxHash, err := PrivateTxHash(inputHashes, outputHashes, externalDataHash, expiry)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}
	p256Pub, p256Sig, err := p256WitnessForTransaction(tx, privateTxHash, requiresP256, options.AllowMissingP256Signature)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}
	amounts, err := derivePublicAmounts(tx)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}
	publicSolAmount, publicSplAmount, publicSplAsset := amounts.sol, amounts.spl, amounts.asset
	programIDHashChain, err := optionalField(tx.ProgramIDHashChain)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("program_id_hashchain: %w", err)
	}
	nullifierBigs, err := proofVariablesToBigInts(nullifiers)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}
	solanaPkHashBigs, err := proofVariablesToBigInts(solanaPkHashes)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}
	publicInputs := PublicInputs{
		Nullifiers:           nullifierBigs,
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		PublicSolAmount:      publicSolAmount,
		PublicSplAmount:      publicSplAmount,
		PublicSplAssetPubkey: publicSplAsset,
		ProgramIDHashChain:   programIDHashChain,
		SolanaPubkeyHash:     new(big.Int).Set(signerHash),
		SolanaPkHashes:       solanaPkHashBigs,
	}
	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}

	utxoRootVars := proofBigIntsToVariables(utxoRoots)
	nullifierRootVars := proofBigIntsToVariables(nullifierRoots)
	inputs := make([]Input, shape.NInputs)
	for i := range inputs {
		inputs[i] = Input{
			Utxo:          inputUtxos[i],
			IsDummy:       isDummyInput[i],
			NullifierPk:   inputNullifierPk[i],
			SolanaPkHash:  solanaPkHashes[i],
			Nullifier:     nullifiers[i],
			UtxoTreeRoot:  utxoRootVars[i],
			NullifierRoot: nullifierRootVars[i],
			State:         MerkleProof{Siblings: statePath[i], Directions: stateDirs[i]},
			NfLowValue:    nfLowValue[i],
			NfNextValue:   nfNextValue[i],
			NfLow:         MerkleProof{Siblings: nfLowPath[i], Directions: nfLowDirs[i]},
		}
	}
	outputs := make([]Output, shape.NOutputs)
	for i := range outputs {
		outputs[i] = Output{
			Utxo:    outputUtxos[i],
			IsDummy: isDummyOutput[i],
			Hash:    outputHashVars[i],
		}
	}

	assignment := &Circuit{
		Shape:                shape,
		Inputs:               inputs,
		Outputs:              outputs,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		NullifierSecret:      sharedNullifierSecret,
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
	return assignment, publicInputs, outputResponses, proofDebug{
		inputHashes:              inputHashes,
		outputHashes:             outputHashes,
		nullifiers:               nullifierBigs,
		inUtxoSignerIndices:      inUtxoSignerIndices,
		requiresP256OwnerWitness: requiresP256,
	}, nil
}

func parseProofInput(input ProofInputRequest) (proofInput, error) {
	nullifierSecret, err := parseField(input.NullifierSecret)
	if err != nil {
		return proofInput{}, fmt.Errorf("nullifier_secret: %w", err)
	}
	parsed, err := parseProofUtxo(input.Utxo, nullifierSecret)
	if err != nil {
		return proofInput{}, err
	}
	return proofInput{
		utxo:            parsed.utxo,
		utxoRequest:     parsed.normalized,
		leafIndex:       input.LeafIndex,
		nullifierSecret: nullifierSecret,
		ownerKeyHash:    parsed.ownerKeyHash,
		nullifierPk:     parsed.nullifierPk,
		isP256:          parsed.isP256,
	}, nil
}

// parsedUtxo holds a ProofUtxoRequest decoded into its circuit fields plus the
// owner material derived alongside it.
type parsedUtxo struct {
	utxo         Utxo
	normalized   ProofUtxoRequest
	ownerKeyHash *big.Int
	nullifierPk  *big.Int
	isP256       bool
}

func parseProofUtxo(input ProofUtxoRequest, inputNullifierSecret *big.Int) (parsedUtxo, error) {
	domain, err := parseField(input.Domain)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("domain: %w", err)
	}
	own, err := parseOwner(input, inputNullifierSecret)
	if err != nil {
		return parsedUtxo{}, err
	}
	assetID, err := parseField(input.AssetID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_id: %w", err)
	}
	assetAmount, err := parseField(input.AssetAmount)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_amount: %w", err)
	}
	blinding, err := parseField(input.Blinding)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("blinding: %w", err)
	}
	dataHash, err := optionalField(input.DataHash)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("data_hash: %w", err)
	}
	policyData, err := optionalField(input.PolicyData)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("policy_data: %w", err)
	}
	policyProgramID, err := optionalField(input.PolicyProgramID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("policy_program_id: %w", err)
	}
	utxo := Utxo{
		Domain:          domain,
		Owner:           own.owner,
		AssetID:         assetID,
		AssetAmount:     assetAmount,
		Blinding:        blinding,
		DataHash:        dataHash,
		PolicyData:      policyData,
		PolicyProgramID: policyProgramID,
	}
	normalized := ProofUtxoRequest{
		Domain:            proofFieldHex(domain),
		Owner:             proofFieldHex(own.owner),
		OwnerSolanaPubkey: strings.TrimPrefix(input.OwnerSolanaPubkey, "0x"),
		OwnerP256Pubkey:   strings.TrimPrefix(input.OwnerP256Pubkey, "0x"),
		AssetID:           proofFieldHex(assetID),
		AssetAmount:       proofFieldHex(assetAmount),
		Blinding:          proofFieldHex(blinding),
		DataHash:          proofFieldHex(dataHash),
		PolicyData:        proofFieldHex(policyData),
		PolicyProgramID:   proofFieldHex(policyProgramID),
	}
	return parsedUtxo{
		utxo:         utxo,
		normalized:   normalized,
		ownerKeyHash: own.keyHash,
		nullifierPk:  own.nullifierPk,
		isP256:       own.isP256,
	}, nil
}

// ownerKey is the key material derived from a UTXO owner's Solana or P256 pubkey.
type ownerKey struct {
	keyHash     *big.Int
	nullifierPk *big.Int
	isP256      bool
}

// ownerFields is a fully resolved UTXO owner: the owner hash plus its key material.
type ownerFields struct {
	owner *big.Int
	ownerKey
}

func parseOwner(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerFields, error) {
	if input.Owner != "" {
		owner, err := parseField(input.Owner)
		if err != nil {
			return ownerFields{}, fmt.Errorf("owner: %w", err)
		}
		if input.OwnerSolanaPubkey == "" && input.OwnerP256Pubkey == "" {
			return ownerFields{owner: owner, ownerKey: ownerKey{keyHash: big.NewInt(0), nullifierPk: big.NewInt(0)}}, nil
		}
		key, err := ownerComponents(input, inputNullifierSecret)
		if err != nil {
			return ownerFields{}, err
		}
		// Both an explicit owner and key components were supplied: they must
		// agree, otherwise the circuit's owner-hash binding would just fail with
		// an opaque error. Reject the inconsistency here with a clear message.
		derived, err := OwnerHash(key.keyHash, key.nullifierPk)
		if err != nil {
			return ownerFields{}, err
		}
		if derived.Cmp(owner) != 0 {
			return ownerFields{}, fmt.Errorf("owner %s does not match the hash of the supplied owner components", input.Owner)
		}
		return ownerFields{owner: owner, ownerKey: key}, nil
	}
	key, err := ownerComponents(input, inputNullifierSecret)
	if err != nil {
		return ownerFields{}, err
	}
	owner, err := OwnerHash(key.keyHash, key.nullifierPk)
	if err != nil {
		return ownerFields{}, err
	}
	return ownerFields{owner: owner, ownerKey: key}, nil
}

func ownerComponents(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerKey, error) {
	hasSolana := strings.TrimSpace(input.OwnerSolanaPubkey) != ""
	hasP256 := strings.TrimSpace(input.OwnerP256Pubkey) != ""
	if hasSolana == hasP256 {
		return ownerKey{}, fmt.Errorf("exactly one owner_solana_pubkey or owner_p256_pubkey is required when owner components are needed")
	}
	var keyHash *big.Int
	var err error
	isP256 := false
	if hasSolana {
		var pubkey [32]byte
		pubkey, err = parseHex32(input.OwnerSolanaPubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
		keyHash, err = SolanaPkHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
	} else {
		var pubkey []byte
		pubkey, err = parseHexBytes(input.OwnerP256Pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		keyHash, err = P256OwnerKeyHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		isP256 = true
	}
	nullifierSecret := inputNullifierSecret
	if nullifierSecret == nil {
		if input.OwnerNullifierSecret == "" {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret is required when owner is omitted")
		}
		nullifierSecret, err = parseField(input.OwnerNullifierSecret)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret: %w", err)
		}
	}
	nullifierPk, err := NullifierPk(nullifierSecret)
	if err != nil {
		return ownerKey{}, err
	}
	return ownerKey{keyHash: keyHash, nullifierPk: nullifierPk, isP256: isP256}, nil
}

func proofExternalDataFieldHash(data proofExternalData) *big.Int {
	hasher := sha256.New()
	hasher.Write([]byte{data.InstructionDiscriminator})
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], data.ExpiryUnixTs)
	hasher.Write(expiry[:])
	hasher.Write(data.SenderViewTag[:])
	var fee [2]byte
	binary.BigEndian.PutUint16(fee[:], data.RelayerFee)
	hasher.Write(fee[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], data.PublicSolAmount)
	hasher.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], data.PublicSplAmount)
	hasher.Write(buf[:])
	hasher.Write(data.UserSolAccount[:])
	hasher.Write(data.UserSplToken[:])
	hasher.Write(data.SplTokenInterface[:])
	hasher.Write(data.EncryptedUtxos)
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

// signedSolAmount produces the signed `public_sol_amount` field value, the
// tornado-nova convention: ext - relayer_fee, where ext is +amount to shield,
// -amount to unshield, 0 to transfer. The relayer fee is always subtracted, so
// a plain transfer pays it (-fee) without being encoded as an unshield. SPP
// builds the same value on-chain from the u64 amount and the shield/unshield
// marker. mode: 0 = transfer, 1 = shield, 2 = unshield.
func signedSolAmount(mode uint8, amount uint64, relayerFee uint16) *big.Int {
	ext := new(big.Int).SetUint64(amount)
	switch mode {
	case 2: // unshield
		ext.Neg(ext)
	case 1: // shield
		// +amount
	default: // transfer: no public SOL movement
		ext.SetInt64(0)
	}
	ext.Sub(ext, new(big.Int).SetUint64(uint64(relayerFee)))
	return SignedToFe(ext)
}

// validatePublicAmountMode rejects modes outside {0=transfer, 1=shield,
// 2=unshield}; the sign helpers are only defined for these values.
func validatePublicAmountMode(mode uint8) error {
	if mode > 2 {
		return fmt.Errorf("spp: invalid public_amount_mode %d (want 0=transfer, 1=shield, 2=unshield)", mode)
	}
	return nil
}

// publicAmounts are the signed public SOL/SPL field values and the SPL asset id,
// as fed to the circuit's balance check.
type publicAmounts struct {
	sol   *big.Int
	spl   *big.Int
	asset *big.Int
}

// derivePublicAmounts validates the mode and derives the signed public amounts
// and SPL asset id in one place. A transfer (mode 0) must carry no public
// amount; shield/unshield set the sign (with the SOL relayer fee folded in).
func derivePublicAmounts(tx ProofTransactionRequest) (publicAmounts, error) {
	if err := validatePublicAmountMode(tx.PublicAmountMode); err != nil {
		return publicAmounts{}, err
	}
	sol := optionalU64(tx.PublicSolAmount)
	spl := optionalU64(tx.PublicSplAmount)
	if tx.PublicAmountMode == 0 && (sol != 0 || spl != 0) {
		return publicAmounts{}, fmt.Errorf("spp: transfer mode carries non-zero public amounts (sol=%d, spl=%d)", sol, spl)
	}
	asset := big.NewInt(0)
	if spl != 0 {
		mint, err := parseHex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		// asset_id = Sha256BE(mint), matching SolAssetID = Sha256BE(default).
		asset = HashToFieldSize(mint[:])
	}
	return publicAmounts{
		sol:   signedSolAmount(tx.PublicAmountMode, sol, tx.RelayerFee),
		spl:   signedSplAmount(tx.PublicAmountMode, spl),
		asset: asset,
	}, nil
}

// signedSplAmount mirrors signedSolAmount for SPL (no relayer fee, which is paid
// in SOL): shield adds +amount, unshield subtracts amount, and a transfer moves
// nothing. A transfer must NOT be treated as a deposit, or it would mint SPL.
func signedSplAmount(mode uint8, amount uint64) *big.Int {
	switch mode {
	case 2: // unshield
		return SignedToFe(new(big.Int).Neg(new(big.Int).SetUint64(amount)))
	case 1: // shield
		return new(big.Int).SetUint64(amount)
	default: // transfer: no public SPL movement
		return big.NewInt(0)
	}
}
