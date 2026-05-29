package spp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"light/light-prover/prover/common"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type ProofBundleRequest struct {
	SolanaSignerPubkey string                    `json:"solana_signer_pubkey"`
	Transactions       []ProofTransactionRequest `json:"transactions"`
}

type ProofTransactionRequest struct {
	Name                     string              `json:"name"`
	InstructionDiscriminator uint8               `json:"instruction_discriminator"`
	ExpiryUnixTs             uint64              `json:"expiry_unix_ts"`
	SenderViewTag            string              `json:"sender_view_tag"`
	RelayerFee               uint16              `json:"relayer_fee"`
	PublicAmountMode         uint8               `json:"public_amount_mode"`
	PublicSolAmount          *uint64             `json:"public_sol_amount"`
	PublicSplAmount          *uint64             `json:"public_spl_amount"`
	PublicSplAssetPubkey     string              `json:"public_spl_asset_pubkey"`
	EncryptedUtxos           string              `json:"encrypted_utxos"`
	UserSolAccount           string              `json:"user_sol_account"`
	UserSplTokenAccount      string              `json:"user_spl_token_account"`
	SplTokenInterface        string              `json:"spl_token_interface"`
	StateEntries             []ProofStateEntry   `json:"state_entries"`
	Inputs                   []ProofInputRequest `json:"inputs"`
	Outputs                  []ProofUtxoRequest  `json:"outputs"`
	UtxoTreeRootIndex        []uint16            `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex   []uint16            `json:"nullifier_tree_root_index"`
	NullifierEntries         []string            `json:"nullifier_entries"`
	ProgramIDHashChain       string              `json:"program_id_hashchain"`
	DataHash                 string              `json:"data_hash"`
	PolicyData               string              `json:"policy_data"`
	P256SignerPubkey         string              `json:"p256_signer_pubkey,omitempty"`
	P256SignatureR           string              `json:"p256_signature_r,omitempty"`
	P256SignatureS           string              `json:"p256_signature_s,omitempty"`
}

type ProofStateEntry struct {
	Index uint64 `json:"index"`
	Hash  string `json:"hash"`
}

type ProofInputRequest struct {
	Utxo      ProofUtxoRequest `json:"utxo"`
	LeafIndex uint64           `json:"leaf_index"`
	// NullifierSecret is the authoritative secret for this input. When set it
	// takes precedence over Utxo.OwnerNullifierSecret, which is only a fallback
	// for recomputing owner components when no input-level secret is supplied.
	// See ownerComponents.
	NullifierSecret string `json:"nullifier_secret"`
}

type ProofUtxoRequest struct {
	Domain            string `json:"domain"`
	Owner             string `json:"owner"`
	OwnerSolanaPubkey string `json:"owner_solana_pubkey"`
	OwnerP256Pubkey   string `json:"owner_p256_pubkey,omitempty"`
	// OwnerNullifierSecret is a fallback used only when this UTXO has no
	// enclosing ProofInputRequest.NullifierSecret (e.g. a bare output UTXO whose
	// owner hash must be recomputed). For inputs, set NullifierSecret instead.
	OwnerNullifierSecret string `json:"owner_nullifier_secret,omitempty"`
	AssetID              string `json:"asset_id"`
	AssetAmount          string `json:"asset_amount"`
	Blinding             string `json:"blinding"`
	DataHash             string `json:"data_hash"`
	PolicyData           string `json:"policy_data"`
	PolicyProgramID      string `json:"policy_program_id"`
}

type ProofBundle struct {
	Shape                 Shape              `json:"shape"`
	SolanaSignerPubkeyHex string             `json:"solana_signer_pubkey"`
	Transactions          []ProofTransaction `json:"transactions"`
}

type ProofTransaction struct {
	Name                    string              `json:"name"`
	ExpiryUnixTs            uint64              `json:"expiry_unix_ts"`
	SenderViewTag           string              `json:"sender_view_tag"`
	Proof                   *common.Proof       `json:"proof"`
	RelayerFee              uint16              `json:"relayer_fee"`
	Nullifiers              []string            `json:"nullifiers"`
	OutputUtxoHashes        []string            `json:"output_utxo_hashes"`
	UtxoTreeRootIndex       []uint16            `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex  []uint16            `json:"nullifier_tree_root_index"`
	PrivateTxHash           string              `json:"private_tx_hash"`
	PublicAmountMode        uint8               `json:"public_amount_mode"`
	PublicSolAmount         *uint64             `json:"public_sol_amount"`
	PublicSplAmount         *uint64             `json:"public_spl_amount"`
	PublicSplAssetPubkey    string              `json:"public_spl_asset_pubkey"`
	EncryptedUtxos          string              `json:"encrypted_utxos"`
	PublicInputHash         string              `json:"public_input_hash"`
	ExternalDataHash        string              `json:"external_data_hash"`
	UserSolAccount          string              `json:"user_sol_account"`
	UserSplTokenAccount     string              `json:"user_spl_token_account"`
	SplTokenInterface       string              `json:"spl_token_interface"`
	InUtxoSignerIndices     []int               `json:"in_utxo_signer_indices"`
	OutputUtxos             []ProofUtxoResponse `json:"output_utxos"`
	DebugInputUtxoHashes    []string            `json:"debug_input_utxo_hashes"`
	DebugOutputUtxoHashes   []string            `json:"debug_output_utxo_hashes"`
	DebugUtxoTreeRoots      []string            `json:"debug_utxo_tree_roots"`
	DebugNullifierTreeRoots []string            `json:"debug_nullifier_tree_roots"`
}

type ProofSigningPayloadBundle struct {
	Shape                 Shape                            `json:"shape"`
	SolanaSignerPubkeyHex string                           `json:"solana_signer_pubkey"`
	Transactions          []ProofSigningPayloadTransaction `json:"transactions"`
}

type ProofSigningPayloadTransaction struct {
	Name                  string `json:"name"`
	PrivateTxHash         string `json:"private_tx_hash"`
	RequiresP256Signature bool   `json:"requires_p256_signature"`
}

type ProofUtxoResponse struct {
	Utxo ProofUtxoRequest `json:"utxo"`
	Hash string           `json:"hash"`
}

type proofInput struct {
	utxo            Utxo
	utxoRequest     ProofUtxoRequest
	leafIndex       uint64
	nullifierSecret *big.Int
	ownerKeyHash    *big.Int
	nullifierPk     *big.Int
	isP256          bool
}

type proofDebug struct {
	inputHashes              []*big.Int
	outputHashes             []*big.Int
	nullifiers               []*big.Int
	inUtxoSignerIndices      []int
	requiresP256OwnerWitness bool
}

type proofExternalData struct {
	InstructionDiscriminator uint8
	SenderViewTag            [32]byte
	RelayerFee               uint16
	PublicSolAmount          uint64
	PublicSplAmount          uint64
	UserSolAccount           [32]byte
	UserSplToken             [32]byte
	SplTokenInterface        [32]byte
	EncryptedUtxos           []byte
}

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
		Name:                    tx.Name,
		ExpiryUnixTs:            tx.ExpiryUnixTs,
		SenderViewTag:           strings.TrimPrefix(tx.SenderViewTag, "0x"),
		Proof:                   &common.Proof{Proof: proof},
		RelayerFee:              tx.RelayerFee,
		Nullifiers:              proofTrimTrailingZeroHexes(debug.nullifiers),
		OutputUtxoHashes:        proofTrimTrailingZeroHexes(debug.outputHashes),
		UtxoTreeRootIndex:       utxoRootIndices,
		NullifierTreeRootIndex:  nullifierRootIndices,
		PrivateTxHash:           proofFieldHex(publicInputs.PrivateTxHash),
		PublicAmountMode:        tx.PublicAmountMode,
		PublicSolAmount:         tx.PublicSolAmount,
		PublicSplAmount:         tx.PublicSplAmount,
		PublicSplAssetPubkey:    strings.TrimPrefix(tx.PublicSplAssetPubkey, "0x"),
		EncryptedUtxos:          strings.TrimPrefix(tx.EncryptedUtxos, "0x"),
		PublicInputHash:         proofFieldHex(publicInputHash),
		ExternalDataHash:        proofFieldHex(publicInputs.ExternalDataHash),
		UserSolAccount:          proofBytesHex(userSolAccount[:]),
		UserSplTokenAccount:     proofBytesHex(userSplTokenAccount[:]),
		SplTokenInterface:       proofBytesHex(splTokenInterface[:]),
		InUtxoSignerIndices:     debug.inUtxoSignerIndices,
		OutputUtxos:             outputUtxos,
		DebugInputUtxoHashes:    proofBigIntHexes(debug.inputHashes),
		DebugOutputUtxoHashes:   proofBigIntHexes(debug.outputHashes),
		DebugUtxoTreeRoots:      proofBigIntHexes(publicInputs.UtxoTreeRoots),
		DebugNullifierTreeRoots: proofBigIntHexes(publicInputs.NullifierRoots),
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
	// Raw unsigned magnitudes; the circuit derives the signed balance effect
	// from public_amount_mode + relayer_fee (all bound as public inputs).
	publicSolAmount := new(big.Int).SetUint64(optionalU64(tx.PublicSolAmount))
	publicSplAmount := new(big.Int).SetUint64(optionalU64(tx.PublicSplAmount))
	publicSplAsset := big.NewInt(0)
	if optionalU64(tx.PublicSplAmount) != 0 {
		publicSplMint, err := parseHex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		publicSplAsset, err = SolanaPkHash(publicSplMint)
		if err != nil {
			return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
	}
	programIDHashChain, err := optionalField(tx.ProgramIDHashChain)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("program_id_hashchain: %w", err)
	}
	dataHash, err := optionalField(tx.DataHash)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("data_hash: %w", err)
	}
	policyData, err := optionalField(tx.PolicyData)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, fmt.Errorf("policy_data: %w", err)
	}

	publicInputs := PublicInputs{
		Nullifiers:           proofVariablesToBigInts(nullifiers),
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     big.NewInt(int64(tx.PublicAmountMode)),
		PublicSolAmount:      publicSolAmount,
		PublicSplAmount:      publicSplAmount,
		RelayerFee:           new(big.Int).SetUint64(uint64(tx.RelayerFee)),
		PublicSplAssetPubkey: publicSplAsset,
		ProgramIDHashChain:   programIDHashChain,
		SolanaPubkeyHash:     new(big.Int).Set(signerHash),
		SolanaPkHashes:       proofVariablesToBigInts(solanaPkHashes),
		DataHash:             dataHash,
		PolicyData:           policyData,
	}
	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return nil, PublicInputs{}, nil, proofDebug{}, err
	}

	assignment := &Circuit{
		Shape:                shape,
		InputUtxos:           inputUtxos,
		InputNullifierPk:     inputNullifierPk,
		IsDummyInput:         isDummyInput,
		StatePath:            statePath,
		StatePathDirs:        stateDirs,
		NfLowValue:           nfLowValue,
		NfNextValue:          nfNextValue,
		NfLowPath:            nfLowPath,
		NfLowPathDirs:        nfLowDirs,
		UtxoTreeRoots:        proofBigIntsToVariables(utxoRoots),
		NullifierRoots:       proofBigIntsToVariables(nullifierRoots),
		OutputUtxos:          outputUtxos,
		IsDummyOutput:        isDummyOutput,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     publicInputs.PublicAmountMode,
		RelayerFee:           publicInputs.RelayerFee,
		NullifierSecret:      sharedNullifierSecret,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		Nullifiers:           nullifiers,
		OutputUtxoHashes:     outputHashVars,
		PrivateTxHash:        privateTxHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashChain:   publicInputs.ProgramIDHashChain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		SolanaPkHashes:       solanaPkHashes,
		DataHash:             publicInputs.DataHash,
		PolicyData:           publicInputs.PolicyData,
		PublicInputHash:      publicInputHash,
	}
	return assignment, publicInputs, outputResponses, proofDebug{
		inputHashes:              inputHashes,
		outputHashes:             outputHashes,
		nullifiers:               proofVariablesToBigInts(nullifiers),
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

func p256WitnessForTransaction(
	tx ProofTransactionRequest,
	privateTxHash *big.Int,
	requiresP256 bool,
	allowMissingSignature bool,
) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	msg := proofFieldBytes(privateTxHash)
	if !requiresP256 && strings.TrimSpace(tx.P256SignerPubkey) == "" {
		return dummyP256Witness(msg[:])
	}
	if allowMissingSignature && (strings.TrimSpace(tx.P256SignerPubkey) == "" || tx.P256SignatureR == "" || tx.P256SignatureS == "") {
		return dummyP256Witness(msg[:])
	}
	pub, err := p256PubkeyWitness(tx.P256SignerPubkey)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signer_pubkey: %w", err)
	}
	if tx.P256SignatureR == "" || tx.P256SignatureS == "" {
		if requiresP256 {
			return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r and p256_signature_s are required for P256 inputs")
		}
		return dummyP256Witness(msg[:])
	}
	r, err := parseP256Scalar(tx.P256SignatureR)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r: %w", err)
	}
	s, err := parseP256Scalar(tx.P256SignatureS)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_s: %w", err)
	}
	return pub, gnarkecdsa.Signature[emulated.P256Fr]{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}, nil
}

func p256PubkeyWitness(compressedHex string) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], error) {
	compressed, err := parseHexBytes(compressedHex)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, err
	}
	if len(compressed) != 33 {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, fmt.Errorf("expected 33-byte compressed P256 public key, got %d", len(compressed))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, fmt.Errorf("invalid compressed P256 public key")
	}
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: emulated.ValueOf[emulated.P256Fp](x),
		Y: emulated.ValueOf[emulated.P256Fp](y),
	}, nil
}

func dummyP256Witness(msg []byte) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	priv, err := fixedP256PrivateKey(big.NewInt(7))
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
		}, gnarkecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		}, nil
}

func fixedP256PrivateKey(d *big.Int) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid P256 private scalar")
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func parseP256Scalar(value string) (*big.Int, error) {
	parsed, err := parseBigInt(value)
	if err != nil {
		return nil, err
	}
	if parsed.Sign() <= 0 || parsed.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("scalar is outside P256 scalar field")
	}
	return parsed, nil
}

func proofExternalDataFieldHash(data proofExternalData) *big.Int {
	hasher := sha256.New()
	hasher.Write([]byte{data.InstructionDiscriminator})
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

func optionalU64(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func optionalField(value string) (*big.Int, error) {
	if value == "" {
		return big.NewInt(0), nil
	}
	return parseField(value)
}

func parseField(value string) (*big.Int, error) {
	out, err := parseBigInt(value)
	if err != nil {
		return nil, err
	}
	if err := validateFieldElement("field", out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return nil, fmt.Errorf("empty field")
	}
	base := 10
	if len(value) > 20 || strings.IndexFunc(value, func(r rune) bool {
		return (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
	}) >= 0 {
		base = 16
	}
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid field %q", value)
	}
	return out, nil
}

func parseHex32(value string) ([32]byte, error) {
	bytes, err := parseHexBytes(value)
	if err != nil {
		return [32]byte{}, err
	}
	if len(bytes) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}
	var out [32]byte
	copy(out[:], bytes)
	return out, nil
}

func parseOptionalHex32(value string) ([32]byte, error) {
	if strings.TrimSpace(value) == "" {
		return [32]byte{}, nil
	}
	return parseHex32(value)
}

func parseHexBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if value == "" {
		return nil, nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func proofZeroUtxo() Utxo {
	return Utxo{
		Domain:          big.NewInt(0),
		Owner:           big.NewInt(0),
		AssetID:         big.NewInt(0),
		AssetAmount:     big.NewInt(0),
		Blinding:        big.NewInt(0),
		DataHash:        big.NewInt(0),
		PolicyData:      big.NewInt(0),
		PolicyProgramID: big.NewInt(0),
	}
}

func toProofCircuitFields(utxo Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:          utxo.Domain,
		Owner:           utxo.Owner,
		AssetID:         utxo.AssetID,
		AssetAmount:     utxo.AssetAmount,
		Blinding:        utxo.Blinding,
		DataHash:        utxo.DataHash,
		PolicyData:      utxo.PolicyData,
		PolicyProgramID: utxo.PolicyProgramID,
	}
}

func proofZeroVariableSlice(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func fillProofPath(path []frontend.Variable, dirs []frontend.Variable, siblings []*big.Int, directions []int) {
	for i := range siblings {
		path[i] = siblings[i]
		dirs[i] = big.NewInt(int64(directions[i]))
	}
}

func proofBigIntsToVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func proofVariablesToBigInts(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case *big.Int:
			out[i] = new(big.Int).Set(v)
		case int:
			out[i] = big.NewInt(int64(v))
		case int64:
			out[i] = big.NewInt(v)
		default:
			panic(fmt.Sprintf("spp: unexpected witness variable type %T", value))
		}
	}
	return out
}

func proofTrimTrailingZeroHexes(values []*big.Int) []string {
	end := len(values)
	for end > 0 && values[end-1].Sign() == 0 {
		end--
	}
	out := make([]string, end)
	for i := 0; i < end; i++ {
		out[i] = proofFieldHex(values[i])
	}
	return out
}

func proofBigIntHexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = proofFieldHex(value)
	}
	return out
}

func proofFieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func proofBytesHex(value []byte) string {
	return fmt.Sprintf("%x", value)
}

func proofFieldBytes(value *big.Int) [32]byte {
	var out [32]byte
	if value == nil {
		return out
	}
	bytes := value.Bytes()
	copy(out[32-len(bytes):], bytes)
	return out
}
