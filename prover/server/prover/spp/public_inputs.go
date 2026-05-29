package spp

// LogicalPublicInputNames is the SPP public-input set, in the order they are
// folded into the public-input hash. public_amount_mode and relayer_fee are
// explicit public inputs so the signed balance effect is derived in-circuit
// from raw magnitudes. expiry_unix_ts is bound transitively via private_tx_hash.
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
	"public_amount_mode",
	"relayer_fee",
	"program_id_hashchain",
	"solana_pubkey_hash",
	"data_hash",
	"policy_data",
	"solana_pk_hashes",
}
