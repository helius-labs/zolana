use solana_address::Address;
use zolana_event::OutputData;
use zolana_interface::instruction::{
    instruction_data::transact::{ExternalDataHash, ResolvedOutput, TransactOutput},
    tag,
};

use crate::error::TransactionError;

/// Transaction-level public data the proofs commit to via `external_data_hash`.
/// The hash is computed by the canonical [`ExternalDataHash`] from the interface
/// crate, so the client and the Solana program agree byte-for-byte. Each output
/// carries its commitment, wire `owner_tag`, and optional ciphertext; the
/// resolved 32-byte owner tags are paired at construction so [`Self::hash`]
/// needs no transaction context and cannot drift from the wire tags.
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
    /// All `M` outputs in tree-append order (SPL change, SOL change, recipients
    /// / dummies). A `None` `data` marks a slot covered by a preceding bundle.
    pub outputs: Vec<TransactOutput>,
    /// The resolved 32-byte owner tag of each output, paired 1:1 with `outputs`
    /// at construction. `hash()` covers these resolved bytes rather than the
    /// wire `OwnerTag`, matching the program's OWNER public input.
    pub resolved_owner_tags: Vec<[u8; 32]>,
    /// Ciphertexts bound to no output commitment; empty for all current flows.
    pub messages: Vec<OutputData>,
}

impl ExternalData {
    pub fn new(
        tx_viewing_pk: [u8; 33],
        salt: [u8; 16],
        outputs: Vec<TransactOutput>,
        resolved_owner_tags: Vec<[u8; 32]>,
        messages: Vec<OutputData>,
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
            outputs,
            resolved_owner_tags,
            messages,
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
    /// Builds [`ResolvedOutput`]s from the outputs paired with their resolved
    /// owner tags, so the client and program hash the identical preimage.
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        if self.outputs.len() != self.resolved_owner_tags.len() {
            return Err(TransactionError::Hash(
                "resolved owner tags do not pair 1:1 with outputs".to_string(),
            ));
        }
        let resolved: Vec<ResolvedOutput> = self
            .outputs
            .iter()
            .zip(self.resolved_owner_tags.iter())
            .map(|(output, owner_tag)| ResolvedOutput {
                utxo_hash: &output.utxo_hash,
                owner_tag: *owner_tag,
                data: output.data.as_deref(),
            })
            .collect();
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
            outputs: &resolved,
            messages: &self.messages,
        }
        .hash()
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))
    }
}
