//! The indexer matches tags without knowing rings, the confirmed call stack names the ring.

use core::future::Future;

use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::{tag, GeneralEvent};
use zolana_event_parser::{
    event_parent, reconstruct_general_event, InstructionGroup, ParsedInstruction,
};
use zolana_interface::{
    instruction::instruction_data::deposit::RingDepositIxData,
    instruction::{settlement_accounts, InterfaceTransfer, TransactIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use zolana_transaction::{ShieldedTransaction, SOL_MINT};

use crate::AuditError;

/// What a confirmed transaction says about its ring, its signers and the value it settled out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOrigin {
    pub ring_invoked: bool,
    /// Contents reconstructed from the exact confirmed SPP instruction and its self-CPI event.
    pub event: ConfirmedEvent,
    /// Fee payer first, every real input owner signs.
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
    /// Capsule bindings from this event's confirmed audited deposit instruction.
    pub deposits: Vec<ConfirmedDeposit>,
}

/// The confirmed instruction selects the recovery path, never indexer metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmedEventKind {
    Deposit,
    Transfer,
    Merge,
}

/// Canonical event contents from a trusted confirmed transaction provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedEvent {
    kind: ConfirmedEventKind,
    event: GeneralEvent,
    /// Set when the origin came from a full confirmed RPC response.
    slot: Option<u64>,
}

impl ConfirmedEvent {
    /// `event` and `kind` must come from the confirmed instruction, not an indexer response.
    /// Custom [`TransactionOrigin`] implementations carry the same trust as the chain RPC.
    pub fn new(kind: ConfirmedEventKind, event: GeneralEvent) -> Self {
        Self {
            kind,
            event,
            slot: None,
        }
    }

    pub fn kind(&self) -> ConfirmedEventKind {
        self.kind
    }

    /// Bind the slot reported by the trusted confirmed transaction provider.
    pub fn with_slot(mut self, slot: u64) -> Self {
        self.slot = Some(slot);
        self
    }

    /// Authenticate every field used for audit and recovery before interpreting ciphertexts.
    fn bind(&self, transaction: &mut ShieldedTransaction) -> Result<(), AuditError> {
        let event = &self.event;
        let viewing_key = transaction
            .tx_viewing_pk
            .as_ref()
            .map(|key| *key.as_bytes())
            .unwrap_or([0; 33]);
        if self.slot.is_some_and(|slot| transaction.slot != slot)
            || transaction.proofless != (self.kind == ConfirmedEventKind::Deposit)
            || viewing_key != event.tx_viewing_pk
            || transaction.salt.unwrap_or_default() != event.salt
            || transaction.messages != event.messages
            || !transaction
                .nullifiers
                .iter()
                .eq(event.inputs.iter().map(|input| &input.nullifier))
            || transaction.output_slots.len() != event.outputs.len()
            || transaction
                .output_slots
                .iter()
                .zip(&event.outputs)
                .enumerate()
                .any(|(index, (indexed, confirmed))| {
                    indexed.view_tag != confirmed.view_tag
                        || indexed.output_context.hash != confirmed.utxo_hash
                        || indexed.payload != confirmed.data
                        || zolana_interface::pda::tree(indexed.output_context.tree_id).to_bytes()
                            != event.output_tree
                        || event.first_output_leaf_index.checked_add(index as u64)
                            != Some(indexed.output_context.leaf_index)
                })
        {
            return Err(AuditError::ConfirmedEventMismatch);
        }
        // Older Photon versions omit an all-zero salt. It is still a valid salt on a confirmed transfer.
        if self.kind == ConfirmedEventKind::Transfer {
            transaction.salt = Some(event.salt);
        }
        Ok(())
    }
}

impl RingOrigin {
    pub fn requires_audit(&self) -> bool {
        self.ring_invoked && self.event.kind == ConfirmedEventKind::Transfer
    }

    /// Bind indexed event contents to this confirmed invocation of `ring`.
    pub fn bind_transaction(
        &self,
        transaction: &mut ShieldedTransaction,
        ring: Address,
    ) -> Result<(), AuditError> {
        if !self.ring_invoked || transaction.ring_program_id != Some(ring) {
            return Err(AuditError::ConfirmedEventMismatch);
        }
        self.event.bind(transaction)
    }
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

/// Reads the origin of the event at `event_index` of a confirmed transaction.
/// Implementations must authenticate the requested signature and reconstruct the
/// event from confirmed chain data independently of the indexer's response.
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
    let (source, emitted) = trusted_event_sources(groups)
        .nth(usize::from(event_index))
        .ok_or(AuditError::InvalidEventIndex(event_index))?;
    let ring_invoked = ring_instructions
        .iter()
        .any(|instruction| core::ptr::eq(*instruction, source));
    let kind = match source.data[0] {
        tag::DEPOSIT | tag::RING_DEPOSIT => ConfirmedEventKind::Deposit,
        tag::MERGE_TRANSACT | tag::RING_MERGE_TRANSACT => ConfirmedEventKind::Merge,
        _ => ConfirmedEventKind::Transfer,
    };
    let event = reconstruct_general_event(source, &emitted.data)
        .map_err(|error| AuditError::InvalidConfirmedEvent(format!("{error:?}")))?;
    Ok(RingOrigin {
        ring_invoked,
        event: ConfirmedEvent::new(kind, event),
        signers: Vec::new(),
        withdrawals: match ring_invoked {
            true => ring_withdrawals_of(&[source])?,
            false => Vec::new(),
        },
        deposits: confirmed_deposits(groups, source, ring)?,
    })
}

/// Bind only capsules whose proof ran in the direct caller of this exact event.
/// A plain deposit may carry arbitrary capsule bytes and grants no binding.
fn confirmed_deposits(
    groups: &[InstructionGroup],
    source: &ParsedInstruction,
    ring: Address,
) -> Result<Vec<ConfirmedDeposit>, AuditError> {
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
        .map_err(|error| AuditError::InvalidDepositData(error.to_string()))?;
    deposit
        .deposits
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let capsule =
                custom_ring_interface::RingDepositAuditCapsule::parse(&entry.encrypted.ciphertext)
                    .map_err(|error| AuditError::InvalidDepositData(error.to_string()))?
                    .filter(|capsule| usize::from(capsule.slot_index) == index)
                    .ok_or_else(|| {
                        AuditError::InvalidDepositData("missing or misplaced capsule".into())
                    })?;
            Ok(ConfirmedDeposit {
                slot_index: capsule.slot_index,
                owner_utxo_hash: entry.owner_utxo_hash,
                capsule_hash: Sha256::digest(&entry.encrypted.ciphertext).into(),
            })
        })
        .collect()
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

fn trusted_event_sources(
    groups: &[InstructionGroup],
) -> impl Iterator<Item = (&ParsedInstruction, &ParsedInstruction)> {
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
                .then_some((parent, instruction))
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

#[cfg(all(test, feature = "solana-rpc"))]
use rpc::confirmed_origin_for;
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
        let slot = transaction.slot;
        let groups = ConfirmedInstructionGroups::try_from(transaction)?;
        let mut origin = RingOrigin {
            signers,
            ..ring_event_origin_in(&groups.groups, event_index, ring)?
        };
        origin.event = origin.event.with_slot(slot);
        Ok(origin)
    }

    pub fn confirmed_origin_for(
        signature: Signature,
        transaction: EncodedConfirmedTransactionWithStatusMeta,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        if !matches!(&transaction.transaction.transaction,
            EncodedTransaction::Json(ui)
                if ui.signatures.first().is_some_and(|value| value == &signature.to_string()))
        {
            return Err(unavailable(
                signature,
                "confirmed transaction signature does not match the request",
            ));
        }
        confirmed_origin(transaction, event_index, ring)
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
            confirmed_origin_for(signature, transaction, event_index, ring)
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
            confirmed_origin_for(signature, transaction, event_index, ring)
        }
    }
}

#[cfg(test)]
mod tests;
