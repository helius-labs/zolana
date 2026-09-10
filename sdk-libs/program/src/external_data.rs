use alloc::vec::Vec;
use core::fmt;

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::HasherError;
use zolana_interface::instruction::instruction_data::transact::{
    validate_interface_transfers, CircuitId, ExternalDataPreimage, InputUtxo, InterfaceTransfer,
    MessageData, TransactIxData, TransactOutput, TransactProof,
};

pub type SettlementAccounts = [[u8; 32]; 2];

#[derive(Debug)]
pub enum ExternalDataHashError {
    Serialize(wincode::Error),
    SettlementAccountCount { expected: usize, provided: usize },
    ResolvedOwnerTagCount { expected: usize, provided: usize },
    Hasher(HasherError),
}

impl fmt::Display for ExternalDataHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(error) => {
                write!(f, "external data prefix serialization failed: {error:?}")
            }
            Self::SettlementAccountCount { expected, provided } => write!(
                f,
                "{provided} settlement account pairs for {expected} interface transfers"
            ),
            Self::ResolvedOwnerTagCount { expected, provided } => {
                write!(f, "{provided} resolved owner tags for {expected} outputs")
            }
            Self::Hasher(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for ExternalDataHashError {}

impl From<HasherError> for ExternalDataHashError {
    fn from(error: HasherError) -> Self {
        Self::Hasher(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactExternalData {
    pub expiry_unix_ts: u64,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutput>,
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    pub messages: Vec<MessageData>,
}

impl From<&TransactIxData> for TransactExternalData {
    fn from(ix: &TransactIxData) -> Self {
        Self {
            expiry_unix_ts: ix.expiry_unix_ts,
            tx_viewing_pk: ix.tx_viewing_pk,
            salt: ix.salt,
            interface_transfers: ix.interface_transfers.clone(),
            data_hash: ix.data_hash,
            ring_data_hash: ix.ring_data_hash,
            outputs: ix.outputs.clone(),
            messages: ix.messages.clone(),
        }
    }
}

impl TransactExternalData {
    pub fn single_output(output: TransactOutput) -> Self {
        Self {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: alloc::vec![output],
            messages: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        validate_interface_transfers(&self.interface_transfers)
            .map_err(|_| wincode::WriteError::Custom("invalid interface transfers"))?;
        Ok(wincode::serialize(self)?)
    }

    pub fn hash(
        &self,
        spp_instruction_discriminator: u8,
        settlement_accounts: &[SettlementAccounts],
        resolved_owner_tags: &[[u8; 32]],
    ) -> Result<[u8; 32], ExternalDataHashError> {
        if settlement_accounts.len() != self.interface_transfers.len() {
            return Err(ExternalDataHashError::SettlementAccountCount {
                expected: self.interface_transfers.len(),
                provided: settlement_accounts.len(),
            });
        }
        if resolved_owner_tags.len() != self.outputs.len() {
            return Err(ExternalDataHashError::ResolvedOwnerTagCount {
                expected: self.outputs.len(),
                provided: resolved_owner_tags.len(),
            });
        }
        let prefix = self.serialize().map_err(ExternalDataHashError::Serialize)?;
        let tag = [spp_instruction_discriminator];
        let mut preimage = ExternalDataPreimage::new(&tag, &prefix);
        for [asset, user] in settlement_accounts {
            preimage.push_settlement(asset, user)?;
        }
        for (output, resolved) in self.outputs.iter().zip(resolved_owner_tags) {
            preimage.push_owner_tag(&output.owner_tag, resolved)?;
        }
        Ok(preimage.finish()?)
    }

    pub fn into_ix_data(
        self,
        private_tx_hash: [u8; 32],
        circuit: CircuitId,
        proof: TransactProof,
        inputs: Vec<InputUtxo>,
    ) -> TransactIxData {
        TransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_pk: self.tx_viewing_pk,
            salt: self.salt,
            interface_transfers: self.interface_transfers,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            outputs: self.outputs,
            messages: self.messages,
            private_tx_hash,
            circuit,
            proof,
            inputs,
        }
    }
}
