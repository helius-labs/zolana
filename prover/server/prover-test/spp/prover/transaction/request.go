package transaction

type ProofTransactionRequest struct {
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
	// InputTreeID and OutputTreeID are the raw u16 tree ids the utxo hashes are
	// bound to: every input is spent from InputTreeID and every output is
	// appended to OutputTreeID. Both default to tree 0.
	InputTreeID      uint16   `json:"input_tree_id"`
	OutputTreeID     uint16   `json:"output_tree_id"`
	NullifierEntries []string `json:"nullifier_entries"`
	DataHash         string   `json:"data_hash"`
	RingDataHash     string   `json:"ring_data_hash"`
	// CompactPadding pads unused slots with compact padding (nullifier and hash
	// 0, left out of the instruction) instead of random dummies. Input slot 0
	// stays a random dummy when the transaction spends nothing.
	CompactPadding bool `json:"compact_padding"`
}

type InterfaceTransferRequest struct {
	IsSpl            bool   `json:"is_spl"`
	IsDeposit        bool   `json:"is_deposit"`
	Asset            string `json:"asset"`
	Amount           uint64 `json:"amount"`
	SplInterfaceBump uint8  `json:"spl_interface_bump"`
	UserAccount      string `json:"user_account"`
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
	OwnerNullifierSecret string `json:"owner_nullifier_secret,omitempty"`
	Asset                string `json:"asset"`
	Amount               string `json:"amount"`
	Blinding             string `json:"blinding"`
	DataHash             string `json:"data_hash"`
	RingDataHash         string `json:"ring_data_hash"`
	RingProgramID        string `json:"ring_program_id"`
}
