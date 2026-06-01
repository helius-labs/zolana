package spp

import (
	"math/big"

	"light/light-prover/prover/common"
)

type ProofBundleRequest struct {
	SolanaSignerPubkey string                    `json:"solana_signer_pubkey"`
	Transactions       []ProofTransactionRequest `json:"transactions"`
	// IncludeDebug populates each transaction's non-authoritative Debug field.
	// It is off by default, so the normal response omits Debug.
	IncludeDebug bool `json:"include_debug,omitempty"`
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
	Asset                string `json:"asset"`
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
	Name                   string              `json:"name"`
	ExpiryUnixTs           uint64              `json:"expiry_unix_ts"`
	SenderViewTag          string              `json:"sender_view_tag"`
	Proof                  *common.Proof       `json:"proof"`
	RelayerFee             uint16              `json:"relayer_fee"`
	Nullifiers             []string            `json:"nullifiers"`
	OutputUtxoHashes       []string            `json:"output_utxo_hashes"`
	UtxoTreeRootIndex      []uint16            `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex []uint16            `json:"nullifier_tree_root_index"`
	PrivateTxHash          string              `json:"private_tx_hash"`
	PublicAmountMode       uint8               `json:"public_amount_mode"`
	PublicSolAmount        *uint64             `json:"public_sol_amount"`
	PublicSplAmount        *uint64             `json:"public_spl_amount"`
	PublicSplAssetPubkey   string              `json:"public_spl_asset_pubkey"`
	EncryptedUtxos         string              `json:"encrypted_utxos"`
	PublicInputHash        string              `json:"public_input_hash"`
	ExternalDataHash       string              `json:"external_data_hash"`
	UserSolAccount         string              `json:"user_sol_account"`
	UserSplTokenAccount    string              `json:"user_spl_token_account"`
	SplTokenInterface      string              `json:"spl_token_interface"`
	InUtxoSignerIndices    []int               `json:"in_utxo_signer_indices"`
	OutputUtxos            []ProofUtxoResponse `json:"output_utxos"`
	Debug                  *ProofDebug         `json:"debug,omitempty"`
}

// ProofDebug carries optional, non-authoritative values useful for debugging a
// bundle. It is populated only when the request sets IncludeDebug, and omitted
// from the normal response.
type ProofDebug struct {
	InputUtxoHashes    []string `json:"input_utxo_hashes"`
	OutputUtxoHashes   []string `json:"output_utxo_hashes"`
	UtxoTreeRoots      []string `json:"utxo_tree_roots"`
	NullifierTreeRoots []string `json:"nullifier_tree_roots"`
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
	leafIndex       uint64
	nullifierSecret *big.Int
	ownerKeyHash    *big.Int
	nullifierPk     *big.Int
	isP256          bool
}

// proofDerivedValues are values computed while building the assignment that the
// transaction response (and the optional debug block) need: authoritative
// outputs like nullifiers and signer indices, plus inputs to the debug block.
type proofDerivedValues struct {
	inputHashes              []*big.Int
	outputHashes             []*big.Int
	nullifiers               []*big.Int
	inUtxoSignerIndices      []int
	requiresP256OwnerWitness bool
}
