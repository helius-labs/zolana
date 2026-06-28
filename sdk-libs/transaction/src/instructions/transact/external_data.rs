use solana_address::Address;
use zolana_interface::instruction::instruction_data::{
    deposit::CpiSignerData,
    transact::{ExternalDataHash, OutputCiphertext},
};

use crate::error::TransactionError;

/// Transaction-level public data the proofs commit to via `external_data_hash`.
/// The hash is computed by the canonical [`ExternalDataHash`] from the interface
/// crate, so the client and the Solana program agree byte-for-byte. The output
/// commitments and the fixed-length ciphertext slots travel in separate vectors
/// (`output_ciphertexts[0]` is the sender bundle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalData {
    pub instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
    pub cpi_signer: Option<CpiSignerData>,
    /// Optional transaction-level program- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-zone
    /// `transact`.
    pub program_data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    /// All `M` output UTXO commitments in tree-append order (SPL change, SOL
    /// change, recipients / dummies).
    pub output_utxo_hashes: Vec<[u8; 32]>,
    /// Fixed-length ciphertext slots: `[0]` the sender bundle, `[1..]` recipient
    /// or dummy slots. Length `1 + (M - SENDER_SLOT_COUNT)`, independent of the
    /// real recipient count.
    pub output_ciphertexts: Vec<OutputCiphertext>,
}

impl ExternalData {
    /// `external_data_hash` via the canonical interface [`ExternalDataHash`].
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        ExternalDataHash {
            spp_instruction_discriminator: self.instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            relayer_fee: self.relayer_fee,
            public_sol_amount: self.public_sol_amount,
            public_spl_amount: self.public_spl_amount,
            user_sol_account: self.user_sol_account.as_array(),
            user_spl_token_account: self.user_spl_token.as_array(),
            spl_token_interface: self.spl_token_interface.as_array(),
            cpi_signer: self.cpi_signer,
            program_data_hash: self.program_data_hash,
            zone_data_hash: self.zone_data_hash,
            output_utxo_hashes: &self.output_utxo_hashes,
            output_ciphertexts: &self.output_ciphertexts,
        }
        .hash()
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))
    }
}
