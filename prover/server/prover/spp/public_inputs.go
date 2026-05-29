package spp

// LogicalPublicInputNames is the SPP public-input set. Non-public implementation
// variables such as expiry, amount mode, and relayer fee are bound through
// private_tx_hash or external_data_hash in v1.
var LogicalPublicInputNames = []string{
	"nullifiers",
	"output_utxo_hashes",
	"utxo_tree_roots",
	"nullifier_tree_roots",
	"private_tx_hash",
	"external_data_hash",
	"public_sol_amount",
	"public_spl_amount",
	"public_spl_asset_pubkey",
	"program_id_hashchain",
	"solana_pubkey_hash",
	"solana_pk_hashes",
}
