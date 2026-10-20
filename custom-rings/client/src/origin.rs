//! Attributing a confirmed transaction to a ring.
//!
//! The indexer matches the auditor view tag without knowing rings. The ring
//! is recovered from the call stack of the confirmed transaction instead.

use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_event::tag;
use zolana_event_parser::{event_parent, InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::instruction_data::deposit::RingDepositIxData,
    instruction::{settlement_accounts, InterfaceTransfer, TransactIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use zolana_transaction::SOL_MINT;

/// What a confirmed transaction says about its ring, its signers, and the value
/// it settled out of the ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOrigin {
    pub ring_invoked: bool,
    /// Required signers, fee payer first. Every real input owner signs.
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
    /// Capsule bindings from this event's confirmed audited deposit instruction.
    pub deposits: Vec<ConfirmedDeposit>,
}

/// An opening authenticated by successful execution of the ring's deposit proof.
/// Only the confirmed instruction parser constructs this binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedDeposit {
    slot_index: u8,
    owner_utxo_hash: [u8; 32],
    capsule_hash: [u8; 32],
}

impl ConfirmedDeposit {
    pub fn slot_index(&self) -> u8 {
        self.slot_index
    }

    pub(crate) fn matches(
        &self,
        capsule: custom_ring_interface::RingDepositAuditCapsule<'_>,
        owner_utxo_hash: &[u8; 32],
    ) -> bool {
        self.slot_index == capsule.slot_index
            && &self.owner_utxo_hash == owner_utxo_hash
            && self.capsule_hash == <[u8; 32]>::from(Sha256::digest(capsule.encode()))
    }
}

/// One public settlement leg out of the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingWithdrawal {
    /// A token account for an SPL leg, a wallet for a SOL leg.
    pub recipient: Address,
    pub asset: Address,
    pub amount: u64,
}

/// Whether a confirmed transaction ran the shielded pool under `ring`.
pub trait TransactionOrigin {
    fn ring_invoked(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<bool, OriginError> {
        Ok(self.origin(signature, event_index, ring)?.ring_invoked)
    }

    fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, OriginError>;
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
    #[error("inner instruction stack height {0} has no parent")]
    InvalidStackHeight(u32),
    #[error("ring transact instruction data is undecodable {0}")]
    InvalidTransactData(String),
    #[error("confirmed audited deposit data is undecodable {0}")]
    InvalidDepositData(String),
    #[error("ring transact settlement accounts do not match its interface transfers")]
    SettlementAccounts,
    #[error("trusted event index {0} is unavailable")]
    InvalidEventIndex(u16),
}

/// Attributes an event in trusted instruction groups from successful confirmed
/// execution. Indexed or caller-provided transaction claims are not evidence.
pub fn ring_event_origin_in(
    groups: &[InstructionGroup],
    event_index: u16,
    ring: Address,
) -> Result<RingOrigin, OriginError> {
    let ring_instructions = ring_instructions_in(groups, ring)?;
    let source = trusted_event_sources(groups)
        .nth(usize::from(event_index))
        .ok_or(OriginError::InvalidEventIndex(event_index))?;
    let ring_invoked = ring_instructions
        .iter()
        .any(|instruction| core::ptr::eq(*instruction, source));
    let withdrawals = if ring_invoked {
        ring_withdrawals_of(&[source])?
    } else {
        Vec::new()
    };
    Ok(RingOrigin {
        ring_invoked,
        signers: Vec::new(),
        withdrawals,
        deposits: confirmed_deposits(groups, source, ring)?,
    })
}

/// Bind only capsules whose proof ran in the direct caller of this exact event.
/// A plain deposit may carry arbitrary capsule bytes and grants no binding.
fn confirmed_deposits(
    groups: &[InstructionGroup],
    source: &ParsedInstruction,
    ring: Address,
) -> Result<Vec<ConfirmedDeposit>, OriginError> {
    if source.data.first() != Some(&tag::RING_DEPOSIT) {
        return Ok(Vec::new());
    }
    let caller = groups.iter().find_map(|group| {
        let index = group
            .inner
            .iter()
            .position(|inner| core::ptr::eq(inner, source))?;
        event_parent(group, index)
    });
    if !caller.is_some_and(|caller| {
        caller.program_id == ring
            && caller.data.first() == Some(&custom_ring_interface::tag::AUDITED_DEPOSIT)
            && caller
                .data
                .get(2 + custom_ring_interface::CustomRingProof::SIZE..)
                == Some(source.data.as_slice())
    }) {
        return Ok(Vec::new());
    }
    let deposit = RingDepositIxData::deserialize(&source.data[1..])
        .map_err(|error| OriginError::InvalidDepositData(error.to_string()))?;
    deposit
        .deposits
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let capsule =
                custom_ring_interface::RingDepositAuditCapsule::parse(&entry.encrypted.ciphertext)
                    .map_err(|error| OriginError::InvalidDepositData(error.to_string()))?
                    .filter(|capsule| usize::from(capsule.slot_index) == index)
                    .ok_or_else(|| {
                        OriginError::InvalidDepositData("missing or misplaced capsule".into())
                    })?;
            Ok(ConfirmedDeposit {
                slot_index: capsule.slot_index,
                owner_utxo_hash: entry.owner_utxo_hash,
                capsule_hash: Sha256::digest(&entry.encrypted.ciphertext).into(),
            })
        })
        .collect()
}

/// `ring_transact` needs the ring's `ring_auth` PDA as signer, so only a pool
/// instruction whose direct caller is `ring` belongs to the ring.
pub fn ring_invoked_in(groups: &[InstructionGroup], ring: Address) -> Result<bool, OriginError> {
    Ok(!ring_instructions_in(groups, ring)?.is_empty())
}

/// The value the ring settled out in the clear, in call order.
pub fn ring_withdrawals_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<RingWithdrawal>, OriginError> {
    ring_withdrawals_of(&ring_instructions_in(groups, ring)?)
}

/// Every pool instruction the ring itself invoked, in call order.
fn ring_instructions_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<&ParsedInstruction>, OriginError> {
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
                .ok_or(OriginError::InvalidStackHeight(height))?;
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
                    && parent
                        .data
                        .first()
                        .copied()
                        .is_some_and(is_event_source_tag))
                .then_some(parent)
            })
    })
}

fn is_event_source_tag(tag_byte: u8) -> bool {
    matches!(
        tag_byte,
        tag::DEPOSIT
            | tag::RING_DEPOSIT
            | tag::TRANSACT
            | tag::RING_TRANSACT
            | tag::RING_AUTHORITY_TRANSACT
            | tag::MERGE_TRANSACT
            | tag::RING_MERGE_TRANSACT
    )
}

/// The public settlement legs of the ring's pool instructions. An SPL leg
/// reports the group's mint and credits a token account rather than a wallet.
fn ring_withdrawals_of(
    instructions: &[&ParsedInstruction],
) -> Result<Vec<RingWithdrawal>, OriginError> {
    let sol_interface = Address::new_from_array(SOL_INTERFACE);
    let cpi_authority = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    let mut withdrawals = Vec::new();
    for instruction in instructions {
        let Some(data) = transact_data(instruction)? else {
            continue;
        };
        let transfers = data.interface_transfers;
        let mut settlement = settlement_accounts(&transfers, data.circuit, &instruction.accounts)
            .ok_or(OriginError::SettlementAccounts)?;
        for transfer in transfers {
            let (group, rest) = settlement.split_at(transfer.settlement_account_count());
            settlement = rest;
            match transfer {
                InterfaceTransfer::SolWithdrawal { amount } => {
                    if group[0] != sol_interface {
                        return Err(OriginError::SettlementAccounts);
                    }
                    withdrawals.push(RingWithdrawal {
                        recipient: group[1],
                        asset: SOL_MINT,
                        amount,
                    });
                }
                InterfaceTransfer::SplWithdrawal { amount, .. } => {
                    if group[0] != cpi_authority {
                        return Err(OriginError::SettlementAccounts);
                    }
                    withdrawals.push(RingWithdrawal {
                        recipient: group[3],
                        asset: group[1],
                        amount,
                    });
                }
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => {}
            }
        }
    }
    Ok(withdrawals)
}

/// `None` for a pool instruction that is not a `ring_transact`.
fn transact_data(instruction: &ParsedInstruction) -> Result<Option<TransactIxData>, OriginError> {
    let Some((&tag::RING_TRANSACT, payload)) = instruction.data.split_first() else {
        return Ok(None);
    };
    let data = TransactIxData::deserialize(payload)
        .map_err(|error| OriginError::InvalidTransactData(error.to_string()))?;
    Ok(Some(data))
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

    use super::{ring_event_origin_in, OriginError, RingOrigin, TransactionOrigin};

    pub const ORIGIN_TRANSACTION_CONFIG: RpcTransactionConfig = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        // A v1 transaction read back at a maximum supported version of 0 comes
        // back as an error rather than as the transaction, so every ring
        // origin lookup would fail the moment the client started sending v1.
        max_supported_transaction_version: Some(1),
    };

    #[must_use]
    pub struct ConfirmedTransaction {
        pub signature: Signature,
        pub transaction: EncodedConfirmedTransactionWithStatusMeta,
    }

    impl ConfirmedTransaction {
        pub fn ring_invoked(self, event_index: u16, ring: Address) -> Result<bool, OriginError> {
            Ok(self.origin(event_index, ring)?.ring_invoked)
        }

        pub fn origin(self, event_index: u16, ring: Address) -> Result<RingOrigin, OriginError> {
            if !matches!(&self.transaction.transaction.transaction,
                EncodedTransaction::Json(ui)
                    if ui.signatures.first().is_some_and(|value| value == &self.signature.to_string()))
            {
                return Err(OriginError::Unavailable {
                    signature: self.signature,
                    message: "confirmed transaction signature does not match the request".into(),
                });
            }
            let signers = signers_of(&self.transaction);
            let groups = ConfirmedInstructionGroups::try_from(self.transaction)?;
            let mut origin = ring_event_origin_in(&groups.groups, event_index, ring)?;
            origin.signers = signers;
            Ok(origin)
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
        fn origin(
            &self,
            signature: Signature,
            event_index: u16,
            ring: Address,
        ) -> Result<RingOrigin, OriginError> {
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
            .origin(event_index, ring)
        }
    }
}
