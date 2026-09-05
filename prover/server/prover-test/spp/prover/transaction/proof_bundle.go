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
	Name                     string                     `json:"name"`
	InstructionDiscriminator uint8                      `json:"instruction_discriminator"`
	ExpiryUnixTs             uint64                     `json:"expiry_unix_ts"`
	SenderViewTag            string                     `json:"sender_view_tag"`
	TxViewingPk              string                     `json:"tx_viewing_pk"`
	Salt                     string                     `json:"salt"`
	InterfaceTransfers       []InterfaceTransferRequest `json:"interface_transfers"`
	EncryptedUtxos           string                     `json:"encrypted_utxos"`
	StateEntries             []ProofStateEntry          `json:"state_entries"`
	Inputs                   []ProofInputRequest        `json:"inputs"`
	Outputs                  []ProofUtxoRequest         `json:"outputs"`
	UtxoTreeRootIndex        []uint16                   `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex   []uint16                   `json:"nullifier_tree_root_index"`
	NullifierEntries         []string                   `json:"nullifier_entries"`
	DataHash                 string                     `json:"data_hash"`
	RingDataHash             string                     `json:"ring_data_hash"`
}

type InterfaceTransferRequest struct {
	IsSpl            bool   `json:"is_spl"`
	IsDeposit        bool   `json:"is_deposit"`
	Asset            string `json:"asset"`
	Amount           uint64 `json:"amount"`
	SplInterfaceBump uint8  `json:"spl_interface_bump"`
	UserAccount      string `json:"user_account"`
	PoolAccount      string `json:"pool_account"`
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
	RingDataHash         string `json:"ring_data_hash"`
	RingProgramID        string `json:"ring_program_id"`
}

type ProofBundle struct {
	Shape          protocol.Shape     `json:"shape"`
	PayerPubkeyHex string             `json:"payer_pubkey"`
	Transactions   []ProofTransaction `json:"transactions"`
}

type ProofTransaction struct {
	Name                   string                     `json:"name"`
	ExpiryUnixTs           uint64                     `json:"expiry_unix_ts"`
	SenderViewTag          string                     `json:"sender_view_tag"`
	TxViewingPk            string                     `json:"tx_viewing_pk"`
	Salt                   string                     `json:"salt"`
	Proof                  *common.Proof              `json:"proof"`
	Nullifiers             []string                   `json:"nullifiers"`
	OutputUtxoHashes       []string                   `json:"output_utxo_hashes"`
	UtxoTreeRootIndex      []uint16                   `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex []uint16                   `json:"nullifier_tree_root_index"`
	PrivateTxHash          string                     `json:"private_tx_hash"`
	InterfaceTransfers     []InterfaceTransferRequest `json:"interface_transfers"`
	EncryptedUtxos         string                     `json:"encrypted_utxos"`
	PublicInputHash        string                     `json:"public_input_hash"`
	ExternalDataHash       string                     `json:"external_data_hash"`

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
	Name          string `json:"name"`
	PrivateTxHash string `json:"private_tx_hash"`
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
	payerHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: payer pubkey hash: %w", err)
	}
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
	payerHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		return nil, fmt.Errorf("spp: payer pubkey hash: %w", err)
	}
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
	if TransactionRequiresP256(tx) {
		return ProofTransaction{}, fmt.Errorf("spp: transaction %q uses the removed P256 ownership rail", tx.Name)
	}
	built, err := buildProofAssignment(ps.Shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		return ProofTransaction{}, err
	}
	assignment, publicInputs, publicInputHash, outputUtxos, transcript :=
		built.witness, built.publicInputs, built.publicInputHash, built.outputUtxos, built.transcript
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
	interfaceTransfers, err := normalizedInterfaceTransfers(tx.InterfaceTransfers)
	if err != nil {
		return ProofTransaction{}, err
	}
	txViewingPk, err := fixedHexBytes(tx.TxViewingPk, 33)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("tx_viewing_pk: %w", err)
	}
	salt, err := fixedHexBytes(tx.Salt, 16)
	if err != nil {
		return ProofTransaction{}, fmt.Errorf("salt: %w", err)
	}

	return ProofTransaction{
		Name:          tx.Name,
		ExpiryUnixTs:  tx.ExpiryUnixTs,
		SenderViewTag: parse.HexString(tx.SenderViewTag),
		TxViewingPk:   parse.BytesHex(txViewingPk),
		Salt:          parse.BytesHex(salt),
		Proof:         &common.Proof{Proof: proof},
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
		InterfaceTransfers:      interfaceTransfers,
		EncryptedUtxos:          parse.HexString(tx.EncryptedUtxos),
		PublicInputHash:         parse.FieldHex(publicInputHash),
		ExternalDataHash:        parse.FieldHex(publicInputs.ExternalDataHash),
		SolanaOwnerPubkeys:      transcript.solanaOwnerPubkeys,
		OutputUtxos:             outputUtxos,
		DebugInputUtxoHashes:    proofBigIntHexes(transcript.inputHashes),
		DebugOutputUtxoHashes:   proofBigIntHexes(transcript.outputHashes),
		DebugUtxoTreeRoots:      proofBigIntHexes(publicInputs.UtxoTreeRoots),
		DebugNullifierTreeRoots: proofBigIntHexes(publicInputs.NullifierTreeRoots),
	}, nil
}

func normalizedInterfaceTransfers(transfers []InterfaceTransferRequest) ([]InterfaceTransferRequest, error) {
	out := make([]InterfaceTransferRequest, 0, len(transfers))
	for position, transfer := range transfers {
		userAccount, err := parse.Hex32(transfer.UserAccount)
		if err != nil {
			return nil, fmt.Errorf("interface_transfers[%d].user_account: %w", position, err)
		}
		normalized := InterfaceTransferRequest{
			IsSpl:            transfer.IsSpl,
			IsDeposit:        transfer.IsDeposit,
			Amount:           transfer.Amount,
			SplInterfaceBump: transfer.SplInterfaceBump,
			UserAccount:      parse.BytesHex(userAccount[:]),
		}
		if transfer.IsSpl {
			asset, err := parse.Hex32(transfer.Asset)
			if err != nil {
				return nil, fmt.Errorf("interface_transfers[%d].asset: %w", position, err)
			}
			poolAccount, err := parse.Hex32(transfer.PoolAccount)
			if err != nil {
				return nil, fmt.Errorf("interface_transfers[%d].pool_account: %w", position, err)
			}
			normalized.Asset = parse.BytesHex(asset[:])
			normalized.PoolAccount = parse.BytesHex(poolAccount[:])
		} else if transfer.Asset != "" {
			return nil, fmt.Errorf("interface_transfers[%d].asset must be empty for SOL", position)
		} else if transfer.PoolAccount != "" {
			return nil, fmt.Errorf("interface_transfers[%d].pool_account must be empty for SOL", position)
		} else if transfer.SplInterfaceBump != 0 {
			return nil, fmt.Errorf("interface_transfers[%d].spl_interface_bump must be zero for SOL", position)
		}
		out = append(out, normalized)
	}
	return out, nil
}

func buildProofSigningPayloadTransaction(shape protocol.Shape, tx ProofTransactionRequest, payerHash *big.Int) (ProofSigningPayloadTransaction, error) {
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		return ProofSigningPayloadTransaction{}, err
	}
	return ProofSigningPayloadTransaction{
		Name:          tx.Name,
		PrivateTxHash: parse.FieldHex(built.publicInputs.PrivateTxHash),
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
