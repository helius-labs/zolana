use solana_address::Address;
use zolana_interface::instruction::{
    instruction_data::transact::{ExternalDataHash, OutputCiphertext},
    tag,
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
    /// Optional transaction-level UTXO- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-zone
    /// `transact`.
    pub data_hash: Option<[u8; 32]>,
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
    pub fn new(
        tx_viewing_pk: [u8; 33],
        salt: [u8; 16],
        output_utxo_hashes: Vec<[u8; 32]>,
        output_ciphertexts: Vec<OutputCiphertext>,
        expiry_unix_ts: u64,
    ) -> Self {
        Self {
            instruction_discriminator: tag::TRANSACT,
            expiry_unix_ts,
            relayer_fee: 0,
            public_sol_amount: None,
            public_spl_amount: None,
            user_sol_account: Address::default(),
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk,
            salt,
            output_utxo_hashes,
            output_ciphertexts,
        }
    }

    pub fn with_public_sol(
        mut self,
        amount: i64,
        user_sol_account: Address,
    ) -> Result<Self, TransactionError> {
        if self.public_sol_amount.is_some() {
            return Err(TransactionError::PublicSolAlreadySet);
        }
        self.public_sol_amount = Some(amount);
        self.user_sol_account = user_sol_account;
        Ok(self)
    }

    pub fn with_public_spl(
        mut self,
        amount: i64,
        user_spl_token: Address,
        spl_token_interface: Address,
    ) -> Result<Self, TransactionError> {
        if self.public_spl_amount.is_some() {
            return Err(TransactionError::PublicSplAlreadySet);
        }
        self.public_spl_amount = Some(amount);
        self.user_spl_token = user_spl_token;
        self.spl_token_interface = spl_token_interface;
        Ok(self)
    }

    pub fn with_zone_hashes(
        mut self,
        data_hash: [u8; 32],
        zone_data_hash: [u8; 32],
    ) -> Result<Self, TransactionError> {
        if self.data_hash.is_some() || self.zone_data_hash.is_some() {
            return Err(TransactionError::ZoneHashesAlreadySet);
        }
        self.data_hash = Some(data_hash);
        self.zone_data_hash = Some(zone_data_hash);
        Ok(self)
    }

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
            data_hash: self.data_hash,
            zone_data_hash: self.zone_data_hash,
            output_utxo_hashes: &self.output_utxo_hashes,
            output_ciphertexts: &self.output_ciphertexts,
        }
        .hash()
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))
    }
}
