//! The indexer matches tags without knowing rings, the confirmed call stack names the ring.

use core::future::Future;

use solana_address::Address;
use solana_signature::Signature;
use zolana_event::tag;
use zolana_event_parser::{event_parent, InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::{settlement_accounts, InterfaceTransfer, TransactIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use zolana_transaction::SOL_MINT;

use crate::AuditError;

/// What a confirmed transaction says about its ring, its signers and the value it settled out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOrigin {
    pub ring_invoked: bool,
    /// Fee payer first, every real input owner signs.
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
}

/// One public settlement leg out of the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingWithdrawal {
    /// A token account for an SPL leg, a wallet for a SOL leg.
    pub recipient: Address,
    pub asset: Address,
    pub amount: u64,
}

/// Reads the origin of the event at `event_index` of a confirmed transaction.
pub trait TransactionOrigin: Sync {
    fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send;
}

/// The trusted event at `event_index` must come from a pool instruction `ring` called directly.
pub fn ring_event_origin_in(
    groups: &[InstructionGroup],
    event_index: u16,
    ring: Address,
) -> Result<RingOrigin, AuditError> {
    let ring_instructions = ring_instructions_in(groups, ring)?;
    let source = trusted_event_sources(groups)
        .nth(usize::from(event_index))
        .ok_or(AuditError::InvalidEventIndex(event_index))?;
    let ring_invoked = ring_instructions
        .iter()
        .any(|instruction| core::ptr::eq(*instruction, source));
    Ok(RingOrigin {
        ring_invoked,
        signers: Vec::new(),
        withdrawals: match ring_invoked {
            true => ring_withdrawals_of(&[source])?,
            false => Vec::new(),
        },
    })
}

/// `ring_transact` needs the ring's `ring_auth` signer, so only the ring's direct callees count.
fn ring_instructions_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<&ParsedInstruction>, AuditError> {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut found = Vec::new();
    for group in groups {
        let mut callers = vec![group.outer.program_id];
        for inner in &group.inner {
            let height = inner.stack_height;
            let parent_depth = usize::try_from(height)
                .ok()
                .and_then(|height| height.checked_sub(2))
                .filter(|depth| *depth < callers.len())
                .ok_or(AuditError::InvalidStackHeight(height))?;
            if inner.program_id == pool && callers[parent_depth] == ring {
                found.push(inner);
            }
            callers.truncate(parent_depth + 1);
            callers.push(inner.program_id);
        }
    }
    Ok(found)
}

fn trusted_event_sources(groups: &[InstructionGroup]) -> impl Iterator<Item = &ParsedInstruction> {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    groups.iter().flat_map(move |group| {
        group
            .inner
            .iter()
            .enumerate()
            .filter_map(move |(index, instruction)| {
                if instruction.program_id != pool
                    || instruction.data.first() != Some(&tag::EMIT_EVENT)
                {
                    return None;
                }
                let parent = event_parent(group, index)?;
                (parent.program_id == pool
                    && parent.data.first().is_some_and(|tag| {
                        matches!(
                            *tag,
                            tag::DEPOSIT
                                | tag::RING_DEPOSIT
                                | tag::TRANSACT
                                | tag::RING_TRANSACT
                                | tag::RING_AUTHORITY_TRANSACT
                                | tag::MERGE_TRANSACT
                                | tag::RING_MERGE_TRANSACT
                        )
                    }))
                .then_some(parent)
            })
    })
}

/// An SPL leg reports its group's mint and credits a token account.
fn ring_withdrawals_of(
    instructions: &[&ParsedInstruction],
) -> Result<Vec<RingWithdrawal>, AuditError> {
    let sol_interface = Address::new_from_array(SOL_INTERFACE);
    let cpi_authority = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    let mut withdrawals = Vec::new();
    for instruction in instructions {
        let Some((&tag::RING_TRANSACT, payload)) = instruction.data.split_first() else {
            continue;
        };
        let data = TransactIxData::deserialize(payload)
            .map_err(|error| AuditError::InvalidTransactData(error.to_string()))?;
        let mut settlement = settlement_accounts(
            &data.interface_transfers,
            data.circuit,
            &instruction.accounts,
        )
        .ok_or(AuditError::SettlementAccounts)?;
        for transfer in data.interface_transfers {
            let (group, rest) = settlement.split_at(transfer.settlement_account_count());
            settlement = rest;
            let (authority, withdrawal) = match transfer {
                InterfaceTransfer::SolWithdrawal { amount } => (
                    sol_interface,
                    RingWithdrawal {
                        recipient: group[1],
                        asset: SOL_MINT,
                        amount,
                    },
                ),
                InterfaceTransfer::SplWithdrawal { amount, .. } => (
                    cpi_authority,
                    RingWithdrawal {
                        recipient: group[3],
                        asset: group[1],
                        amount,
                    },
                ),
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => {
                    continue
                }
            };
            if group[0] != authority {
                return Err(AuditError::SettlementAccounts);
            }
            withdrawals.push(withdrawal);
        }
    }
    Ok(withdrawals)
}

#[cfg(feature = "solana-rpc")]
pub use rpc::{confirmed_origin, ORIGIN_TRANSACTION_CONFIG};

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
    use zolana_client::{AsyncSolanaRpc, Blocking, ConfirmedInstructionGroups, SolanaRpc};

    use super::{ring_event_origin_in, RingOrigin, TransactionOrigin};
    use crate::AuditError;

    /// A v1 transaction read back at a maximum version of 0 is an error, not the transaction.
    pub const ORIGIN_TRANSACTION_CONFIG: RpcTransactionConfig = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(1),
    };

    /// The origin of the event at `event_index` with the transaction's required signers.
    pub fn confirmed_origin(
        transaction: EncodedConfirmedTransactionWithStatusMeta,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        let signers = signers_of(&transaction);
        let groups = ConfirmedInstructionGroups::try_from(transaction)?;
        Ok(RingOrigin {
            signers,
            ..ring_event_origin_in(&groups.groups, event_index, ring)?
        })
    }

    /// The first `num_required_signatures` keys, an unknown encoding names no signer.
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

    fn unavailable(signature: Signature, error: impl ToString) -> AuditError {
        AuditError::Unavailable {
            signature,
            message: error.to_string(),
        }
    }

    impl TransactionOrigin for AsyncSolanaRpc {
        async fn origin(
            &self,
            signature: Signature,
            event_index: u16,
            ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            let transaction = self
                .client()
                .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
                .await
                .map_err(|error| unavailable(signature, error))?;
            confirmed_origin(transaction, event_index, ring)
        }
    }

    /// The read runs on Tokio's blocking pool, as every other `Blocking` call does.
    impl TransactionOrigin for Blocking<SolanaRpc> {
        async fn origin(
            &self,
            signature: Signature,
            event_index: u16,
            ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            let rpc = self.clone();
            let transaction = tokio::task::spawn_blocking(move || {
                rpc.inner()
                    .client()
                    .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
            })
            .await
            .map_err(|error| unavailable(signature, error))?
            .map_err(|error| unavailable(signature, error))?;
            confirmed_origin(transaction, event_index, ring)
        }
    }
}

#[cfg(test)]
mod tests;
