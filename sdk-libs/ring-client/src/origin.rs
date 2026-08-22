//! Attributing a confirmed transaction to a ring.
//!
//! The indexer matches the auditor view tag without knowing rings. The ring
//! is recovered from the call stack of the confirmed transaction instead.

use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_event::InstructionGroup;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

/// What a confirmed transaction says about its ring and its signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOrigin {
    pub ring_invoked: bool,
    /// Required signers, fee payer first. Every real input owner signs.
    pub signers: Vec<Address>,
}

/// Whether a confirmed transaction ran the shielded pool under `ring`.
pub trait TransactionOrigin {
    fn ring_invoked(&self, signature: Signature, ring: Address) -> Result<bool, OriginError> {
        Ok(self.origin(signature, ring)?.ring_invoked)
    }

    fn origin(&self, signature: Signature, ring: Address) -> Result<RingOrigin, OriginError>;
}

#[derive(Debug, Error)]
pub enum OriginError {
    #[error("transaction {signature} is unavailable {message}")]
    Unavailable {
        signature: Signature,
        message: String,
    },
    #[error(transparent)]
    Decode(#[from] ClientError),
    #[error("inner instruction carries no stack height")]
    MissingStackHeight,
    #[error("inner instruction stack height {0} has no parent")]
    InvalidStackHeight(u32),
}

/// `ring_transact` needs the ring's `ring_auth` PDA as signer, so only a pool
/// instruction whose direct caller is `ring` belongs to the ring.
pub fn ring_invoked_in(groups: &[InstructionGroup], ring: Address) -> Result<bool, OriginError> {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    for group in groups {
        let mut callers = vec![group.outer.program_id];
        for inner in &group.inner {
            let height = inner.stack_height.ok_or(OriginError::MissingStackHeight)?;
            let parent_depth = usize::try_from(height)
                .ok()
                .and_then(|height| height.checked_sub(2))
                .filter(|depth| *depth < callers.len())
                .ok_or(OriginError::InvalidStackHeight(height))?;
            if inner.program_id == pool && callers[parent_depth] == ring {
                return Ok(true);
            }
            callers.truncate(parent_depth + 1);
            callers.push(inner.program_id);
        }
    }
    Ok(false)
}

#[cfg(feature = "solana-rpc")]
pub use rpc::{ConfirmedTransaction, ORIGIN_TRANSACTION_CONFIG};

#[cfg(feature = "solana-rpc")]
mod rpc {
    use solana_address::Address;
    use solana_commitment_config::CommitmentConfig;
    use solana_rpc_client_api::config::RpcTransactionConfig;
    use solana_signature::Signature;
    use solana_transaction_status_client_types::{
        EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiMessage,
        UiTransactionEncoding,
    };
    use zolana_client::{ConfirmedInstructionGroups, SolanaRpc};

    use super::{ring_invoked_in, OriginError, RingOrigin, TransactionOrigin};

    pub const ORIGIN_TRANSACTION_CONFIG: RpcTransactionConfig = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    #[must_use]
    pub struct ConfirmedTransaction {
        pub signature: Signature,
        pub transaction: EncodedConfirmedTransactionWithStatusMeta,
    }

    impl ConfirmedTransaction {
        pub fn ring_invoked(self, ring: Address) -> Result<bool, OriginError> {
            Ok(self.origin(ring)?.ring_invoked)
        }

        pub fn origin(self, ring: Address) -> Result<RingOrigin, OriginError> {
            let signers = signers_of(&self.transaction);
            let groups = ConfirmedInstructionGroups::from_confirmed_transaction(
                &self.signature,
                self.transaction,
            )?;
            Ok(RingOrigin {
                ring_invoked: ring_invoked_in(&groups.groups, ring)?,
                signers,
            })
        }
    }

    /// The first `num_required_signatures` account keys. An unknown encoding
    /// names no signer.
    fn signers_of(transaction: &EncodedConfirmedTransactionWithStatusMeta) -> Vec<Address> {
        let EncodedTransaction::Json(ui) = &transaction.transaction.transaction else {
            return Vec::new();
        };
        let (keys, required) = match &ui.message {
            UiMessage::Raw(raw) => (
                raw.account_keys.clone(),
                usize::from(raw.header.num_required_signatures),
            ),
            UiMessage::Parsed(parsed) => (
                parsed
                    .account_keys
                    .iter()
                    .map(|key| key.pubkey.clone())
                    .collect(),
                parsed.account_keys.iter().filter(|key| key.signer).count(),
            ),
        };
        keys.into_iter()
            .take(required)
            .filter_map(|key| key.parse().ok())
            .collect()
    }

    impl TransactionOrigin for SolanaRpc {
        fn origin(&self, signature: Signature, ring: Address) -> Result<RingOrigin, OriginError> {
            let transaction = self
                .client()
                .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
                .map_err(|error| OriginError::Unavailable {
                    signature,
                    message: error.to_string(),
                })?;
            ConfirmedTransaction {
                signature,
                transaction,
            }
            .origin(ring)
        }
    }
}
