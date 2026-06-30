package transaction

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
)

type ProofBundleRequest struct {
	PayerPubkey  string                    `json:"payer_pubkey"`
	Transactions []ProofTransactionRequest `json:"transactions"`
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
	DataHash                 string              `json:"data_hash"`
	ZoneDataHash             string              `json:"zone_data_hash"`
	P256OwnerPubkey          string              `json:"p256_owner_pubkey,omitempty"`
	P256SignatureR           string              `json:"p256_signature_r,omitempty"`
	P256SignatureS           string              `json:"p256_signature_s,omitempty"`
}

type ProofStateEntry struct {
	Index uint64 `json:"index"`
	Hash  string `json:"hash"`
}

type ProofInputRequest struct {
	Utxo            ProofUtxoRequest `json:"utxo"`
	LeafIndex       uint64           `json:"leaf_index"`
	NullifierSecret string           `json:"nullifier_secret"`
}

type ProofUtxoRequest struct {
	Domain               string `json:"domain"`
	Owner                string `json:"owner"`
	OwnerSolanaPubkey    string `json:"owner_solana_pubkey"`
	OwnerP256Pubkey      string `json:"owner_p256_pubkey,omitempty"`
	OwnerNullifierSecret string `json:"owner_nullifier_secret,omitempty"`
	Asset                string `json:"asset"`
	Amount               string `json:"amount"`
	Blinding             string `json:"blinding"`
	DataHash             string `json:"data_hash"`
	ZoneDataHash         string `json:"zone_data_hash"`
	ZoneProgramID        string `json:"zone_program_id"`
}

type ProofBundle struct {
	Shape          protocol.Shape     `json:"shape"`
	PayerPubkeyHex string             `json:"payer_pubkey"`
	Transactions   []ProofTransaction `json:"transactions"`
}

type ProofTransaction struct {
	Name                   string        `json:"name"`
	ExpiryUnixTs           uint64        `json:"expiry_unix_ts"`
	SenderViewTag          string        `json:"sender_view_tag"`
	Proof                  *common.Proof `json:"proof"`
	RelayerFee             uint16        `json:"relayer_fee"`
	Nullifiers             []string      `json:"nullifiers"`
	OutputUtxoHashes       []string      `json:"output_utxo_hashes"`
	UtxoTreeRootIndex      []uint16      `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex []uint16      `json:"nullifier_tree_root_index"`
	PrivateTxHash          string        `json:"private_tx_hash"`
	PublicAmountMode       uint8         `json:"public_amount_mode"`
	PublicSolAmount        *uint64       `json:"public_sol_amount"`
	PublicSplAmount        *uint64       `json:"public_spl_amount"`
	PublicSplAssetPubkey   string        `json:"public_spl_asset_pubkey"`
	EncryptedUtxos         string        `json:"encrypted_utxos"`
	RequiresP256           bool          `json:"requires_p256"`
	PublicInputHash        string        `json:"public_input_hash"`
	ExternalDataHash       string        `json:"external_data_hash"`
	UserSolAccount         string        `json:"user_sol_account"`
	UserSplTokenAccount    string        `json:"user_spl_token_account"`
	SplTokenInterface      string        `json:"spl_token_interface"`

	SolanaOwnerPubkeys      []string            `json:"solana_owner_pubkeys"`
	OutputUtxos             []ProofUtxoResponse `json:"output_utxos"`
	DebugInputUtxoHashes    []string            `json:"debug_input_utxo_hashes"`
	DebugOutputUtxoHashes   []string            `json:"debug_output_utxo_hashes"`
	DebugUtxoTreeRoots      []string            `json:"debug_utxo_tree_roots"`
	DebugNullifierTreeRoots []string            `json:"debug_nullifier_tree_roots"`
}

type ProofSigningPayloadBundle struct {
	Shape          protocol.Shape                   `json:"shape"`
	PayerPubkeyHex string                           `json:"payer_pubkey"`
	Transactions   []ProofSigningPayloadTransaction `json:"transactions"`
}

type ProofSigningPayloadTransaction struct {
	Name                  string `json:"name"`
	PrivateTxHash         string `json:"private_tx_hash"`
	P256MessageHash       string `json:"p256_message_hash"`
	RequiresP256Signature bool   `json:"requires_p256_signature"`
}

type ProofUtxoResponse struct {
	Utxo ProofUtxoRequest `json:"utxo"`
	Hash string           `json:"hash"`
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
	payerPubkey, err := parse.Hex32(request.PayerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: payer pubkey: %w", err)
	}
	payerHash := protocol.Sha256BEField(payerPubkey[:])
	out := &ProofBundle{
		Shape:          ps.Shape,
		PayerPubkeyHex: parse.BytesHex(payerPubkey[:]),
	}
	for _, tx := range request.Transactions {
		proved, err := buildProofTransaction(ps, tx, payerHash)
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
	payerPubkey, err := parse.Hex32(request.PayerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: payer pubkey: %w", err)
	}
	payerHash := protocol.Sha256BEField(payerPubkey[:])
	out := &ProofSigningPayloadBundle{
		Shape:          ps.Shape,
		PayerPubkeyHex: parse.BytesHex(payerPubkey[:]),
	}
	for _, tx := range request.Transactions {
		payload, err := buildProofSigningPayloadTransaction(ps.Shape, tx, payerHash)
		if err != nil {
			return nil, fmt.Errorf("spp: transaction %q: %w", tx.Name, err)
		}
		out.Transactions = append(out.Transactions, payload)
	}
	return out, nil
}

func buildProofTransaction(ps *ProofSystem, tx ProofTransactionRequest, payerHash *big.Int) (ProofTransaction, error) {
	if ps.RequiresP256 != TransactionRequiresP256(tx) {
		return ProofTransaction{}, fmt.Errorf(
			"spp: proving system rail mismatch: system requiresP256=%v, transaction requiresP256=%v",
			ps.RequiresP256, TransactionRequiresP256(tx),
		)
	}
	built, err := buildProofAssignment(ps.Shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		return ProofTransaction{}, err
	}
	assignment, publicInputs, publicInputHash, outputUtxos, transcript :=
		built.circuit, built.publicInputs, built.publicInputHash, built.outputUtxos, built.transcript
	proof, err := Prove(ps, assignment)
	if err != nil {
		return ProofTransaction{}, err
	}
	if err := Verify(ps, assignment, proof); err != nil {
		return ProofTransaction{}, err
	}

	utxoRootIndices, err := proofRootIndices(tx.UtxoTreeRootIndex, len(tx.Inputs), "utxo_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}
	nullifierTreeRootIndices, err := proofRootIndices(tx.NullifierTreeRootIndex, len(tx.Inputs), "nullifier_tree_root_index")
	if err != nil {
		return ProofTransaction{}, err
	}
	userSolAccount, err := parse.OptionalHex32(tx.UserSolAccount)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("user_sol_account: %w", err)
	}
	userSplTokenAccount, err := parse.OptionalHex32(tx.UserSplTokenAccount)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("user_spl_token_account: %w", err)
	}
	splTokenInterface, err := parse.OptionalHex32(tx.SplTokenInterface)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("spl_token_interface: %w", err)
	}

	return ProofTransaction{
		Name:          tx.Name,
		ExpiryUnixTs:  tx.ExpiryUnixTs,
		SenderViewTag: parse.HexString(tx.SenderViewTag),
		Proof:         &common.Proof{Proof: proof},
		RelayerFee:    tx.RelayerFee,
		// Real-length public transcript. transcript.{nullifiers,outputHashes} are
		// padded to the circuit shape (reals first, then dummy slots), but the
		// on-chain TransactData wants the real-length arrays (it pads
		// internally) and requires the nullifier count to match the
		// root-index counts, which are already real-length. Slicing at the
		// source makes every bundle consumer correct instead of each one
		// re-slicing (the e2e fixture builder did the latter).
		Nullifiers:              proofBigIntHexes(transcript.nullifiers[:len(tx.Inputs)]),
		OutputUtxoHashes:        proofBigIntHexes(transcript.outputHashes[:len(tx.Outputs)]),
		UtxoTreeRootIndex:       utxoRootIndices,
		NullifierTreeRootIndex:  nullifierTreeRootIndices,
		PrivateTxHash:           parse.FieldHex(publicInputs.PrivateTxHash),
		PublicAmountMode:        tx.PublicAmountMode,
		PublicSolAmount:         tx.PublicSolAmount,
		PublicSplAmount:         tx.PublicSplAmount,
		PublicSplAssetPubkey:    parse.HexString(tx.PublicSplAssetPubkey),
		EncryptedUtxos:          parse.HexString(tx.EncryptedUtxos),
		RequiresP256:            transcript.requiresP256OwnerWitness,
		PublicInputHash:         parse.FieldHex(publicInputHash),
		ExternalDataHash:        parse.FieldHex(publicInputs.ExternalDataHash),
		UserSolAccount:          parse.BytesHex(userSolAccount[:]),
		UserSplTokenAccount:     parse.BytesHex(userSplTokenAccount[:]),
		SplTokenInterface:       parse.BytesHex(splTokenInterface[:]),
		SolanaOwnerPubkeys:      transcript.solanaOwnerPubkeys,
		OutputUtxos:             outputUtxos,
		DebugInputUtxoHashes:    proofBigIntHexes(transcript.inputHashes),
		DebugOutputUtxoHashes:   proofBigIntHexes(transcript.outputHashes),
		DebugUtxoTreeRoots:      proofBigIntHexes(publicInputs.UtxoTreeRoots),
		DebugNullifierTreeRoots: proofBigIntHexes(publicInputs.NullifierTreeRoots),
	}, nil
}

func buildProofSigningPayloadTransaction(shape protocol.Shape, tx ProofTransactionRequest, payerHash *big.Int) (ProofSigningPayloadTransaction, error) {
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{
		AllowMissingP256Signature: true,
	})
	if err != nil {
		return ProofSigningPayloadTransaction{}, err
	}
	return ProofSigningPayloadTransaction{
		Name:                  tx.Name,
		PrivateTxHash:         parse.FieldHex(built.publicInputs.PrivateTxHash),
		P256MessageHash:       parse.BytesHex(built.p256MessageDigest[:]),
		RequiresP256Signature: built.transcript.requiresP256OwnerWitness,
	}, nil
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
