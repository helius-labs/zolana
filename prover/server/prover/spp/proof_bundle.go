package spp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"light/light-prover/prover/common"
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
		proved, err := buildProofTransaction(ps, tx, signerHash, request.IncludeDebug)
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

func buildProofTransaction(ps *ProofSystem, tx ProofTransactionRequest, signerHash *big.Int, includeDebug bool) (ProofTransaction, error) {
	// Validate request shape before the expensive proof run so a length
	// mismatch fails fast instead of wasting a full Prove.
	utxoRootIndices, err := proofRootIndices(tx.UtxoTreeRootIndex, len(tx.Inputs), "utxo_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}
	nullifierRootIndices, err := proofRootIndices(tx.NullifierTreeRootIndex, len(tx.Inputs), "nullifier_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}

	built, err := buildProofAssignment(ps.Shape, tx, signerHash, proofBuildOptions{})
	if err != nil {
		return ProofTransaction{}, err
	}
	publicInputs, derived := built.publicInputs, built.derived
	proof, err := Prove(ps, built.circuit)
	if err != nil {
		return ProofTransaction{}, err
	}
	if err := Verify(ps, built.circuit, proof); err != nil {
		return ProofTransaction{}, err
	}

	var debugInfo *ProofDebug
	if includeDebug {
		debugInfo = &ProofDebug{
			InputUtxoHashes:    proofBigIntHexes(derived.inputHashes),
			OutputUtxoHashes:   proofBigIntHexes(derived.outputHashes),
			UtxoTreeRoots:      proofBigIntHexes(publicInputs.UtxoTreeRoots),
			NullifierTreeRoots: proofBigIntHexes(publicInputs.NullifierRoots),
		}
	}

	return ProofTransaction{
		Name:                   tx.Name,
		ExpiryUnixTs:           tx.ExpiryUnixTs,
		SenderViewTag:          strings.TrimPrefix(tx.SenderViewTag, "0x"),
		Proof:                  &common.Proof{Proof: proof},
		RelayerFee:             tx.RelayerFee,
		Nullifiers:             proofTrimTrailingZeroHexes(derived.nullifiers),
		OutputUtxoHashes:       proofTrimTrailingZeroHexes(derived.outputHashes),
		UtxoTreeRootIndex:      utxoRootIndices,
		NullifierTreeRootIndex: nullifierRootIndices,
		PrivateTxHash:          proofFieldHex(publicInputs.PrivateTxHash),
		PublicAmountMode:       tx.PublicAmountMode,
		PublicSolAmount:        tx.PublicSolAmount,
		PublicSplAmount:        tx.PublicSplAmount,
		PublicSplAssetPubkey:   strings.TrimPrefix(tx.PublicSplAssetPubkey, "0x"),
		EncryptedUtxos:         strings.TrimPrefix(tx.EncryptedUtxos, "0x"),
		PublicInputHash:        proofFieldHex(built.publicInputHash),
		ExternalDataHash:       proofFieldHex(publicInputs.ExternalDataHash),
		UserSolAccount:         proofBytesHex(built.external.userSolAccount[:]),
		UserSplTokenAccount:    proofBytesHex(built.external.userSplToken[:]),
		SplTokenInterface:      proofBytesHex(built.external.splTokenInterface[:]),
		InUtxoSignerIndices:    derived.inUtxoSignerIndices,
		OutputUtxos:            built.outputUtxos,
		Debug:                  debugInfo,
	}, nil
}

func buildProofSigningPayloadTransaction(shape Shape, tx ProofTransactionRequest, signerHash *big.Int) (ProofSigningPayloadTransaction, error) {
	built, err := buildProofAssignment(shape, tx, signerHash, proofBuildOptions{
		AllowMissingP256Signature: true,
	})
	if err != nil {
		return ProofSigningPayloadTransaction{}, err
	}
	return ProofSigningPayloadTransaction{
		Name:                  tx.Name,
		PrivateTxHash:         proofFieldHex(built.publicInputs.PrivateTxHash),
		RequiresP256Signature: built.derived.requiresP256OwnerWitness,
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
