use light_array_map::ArrayMap;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::{primitives::hash_bytes, Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    event::SplTransfer,
    instruction::{
        DepositAssetKind, DepositEntryRef, DepositIxDataRef, ZoneDepositEntryRef,
        ZoneDepositIxDataRef, MAX_DEPOSIT_ASSETS,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::{
    account::DepositAccounts,
    event::{
        emit_deposit_event, encrypted_zone_output_utxo, proofless_output_utxo, DepositEvent,
        ProoflessOutputCtx,
    },
};
use crate::instructions::hash::{field_from_u64, UTXO_DOMAIN_FIELD};

#[derive(Clone, Copy)]
enum ProcessingEntry<'a> {
    Default(DepositEntryRef<'a>),
    Zone(ZoneDepositEntryRef<'a>),
}

#[profile]
pub fn process_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = DepositIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    process_deposit_internal::<false>(
        accounts,
        &data.assets,
        data.deposits.into_iter().map(ProcessingEntry::Default),
    )
}

pub fn process_zone_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = ZoneDepositIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    process_deposit_internal::<true>(
        accounts,
        &data.assets,
        data.deposits.into_iter().map(ProcessingEntry::Zone),
    )
}

fn process_deposit_internal<'a, const HAS_ZONE: bool>(
    accounts: &mut [AccountView],
    assets: &[DepositAssetKind],
    entries: impl ExactSizeIterator<Item = ProcessingEntry<'a>>,
) -> ProgramResult {
    let entry_count = entries.len();
    if entry_count == 0 {
        return Err(ShieldedPoolError::EmptyDepositBatch.into());
    }

    let (parsed, zone_program_id) =
        DepositAccounts::validate_and_parse::<HAS_ZONE>(&crate::ID, accounts, assets)?;

    let zero = [0u8; 32];
    let zone_program_id_field = match &zone_program_id {
        Some(program_id) => hash_bytes(program_id)?,
        None => zero,
    };
    let mut output_tree = [0u8; 32];
    output_tree.copy_from_slice(parsed.tree.address().as_ref());

    let mut asset_sums: ArrayMap<u8, u64, MAX_DEPOSIT_ASSETS> = ArrayMap::new();
    let mut outputs = Vec::with_capacity(entry_count);
    let mut utxo_hashes = Vec::with_capacity(entry_count);

    for processing_entry in entries {
        let (asset_index, amount) = match processing_entry {
            ProcessingEntry::Default(entry) => (entry.asset_index, entry.amount),
            ProcessingEntry::Zone(entry) => (entry.asset_index, entry.amount),
        };
        let group = parsed
            .groups
            .get(usize::from(asset_index))
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;

        let (data_hash, zone_data_hash, owner_utxo_hash) = match processing_entry {
            ProcessingEntry::Default(entry) => {
                let data_hash = entry.utxo_data.map_or(&zero, |utxo| utxo.data_hash);
                let owner_utxo_hash =
                    Poseidon::hashv(&[entry.owner.as_slice(), entry.blinding.as_slice()])
                        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
                (data_hash, &zero, owner_utxo_hash)
            }
            ProcessingEntry::Zone(entry) => (
                entry.data_hash.unwrap_or(&zero),
                entry.zone_data_hash,
                *entry.owner_utxo_hash,
            ),
        };
        let zone_hash = hash_with_program_id(zone_data_hash, &zone_program_id_field)?;
        let utxo_hash = Poseidon::hashv(&[
            UTXO_DOMAIN_FIELD.as_slice(),
            group.asset_field.as_slice(),
            field_from_u64(amount).as_slice(),
            data_hash.as_slice(),
            zone_hash.as_slice(),
            owner_utxo_hash.as_slice(),
        ])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        utxo_hashes.push(utxo_hash);

        match asset_sums.get_mut_by_key(&asset_index) {
            Some(total) => {
                *total = total
                    .checked_add(amount)
                    .ok_or(ShieldedPoolError::DepositAmountOverflow)?;
            }
            None => {
                asset_sums.insert(asset_index, amount, ShieldedPoolError::TooManyDepositAssets)?;
            }
        }

        let output_ctx = ProoflessOutputCtx {
            utxo_hash,
            asset: group.asset,
        };
        outputs.push(match processing_entry {
            ProcessingEntry::Default(entry) => proofless_output_utxo(entry, output_ctx),
            ProcessingEntry::Zone(entry) => encrypted_zone_output_utxo(
                entry,
                output_ctx,
                zone_program_id.ok_or(ShieldedPoolError::InvalidZoneConfig)?,
            ),
        });
    }

    let mut tree =
        TreeAccount::from_account_view_mut(parsed.tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(ShieldedPoolError::from)?;
    let first_output_leaf_index = tree.utxo_tree().next_index();

    // One batch append: only the last leaf hashes up to the root, so a batch
    // costs one root recomputation instead of one per entry.
    tree.utxo_tree()
        .append_batch(utxo_hashes.iter())
        .map_err(ShieldedPoolError::from)?;
    drop(tree);

    // Every settlement group must be funded by at least one entry; unused
    // groups would otherwise pass validation without settling.
    if asset_sums.len() != parsed.groups.len() {
        return Err(ShieldedPoolError::UnreferencedDepositAsset.into());
    }

    let mut spl_transfers = Vec::with_capacity(asset_sums.len());
    for slot in 0..asset_sums.len() {
        let (asset_index, total) = asset_sums
            .get_by_index(slot)
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;
        let group = parsed
            .groups
            .get(usize::from(*asset_index))
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;

        if !group.settlement.is_deposit() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        if *total > 0 {
            group.settlement.settle(*total)?;
        }
        spl_transfers.push(SplTransfer {
            is_deposit: true,
            amount: *total,
            asset: group.settlement.spl_asset()?,
        });
    }

    emit_deposit_event(DepositEvent {
        outputs,
        spl_transfers,
        first_output_leaf_index,
        output_tree,
    })
}

fn hash_with_program_id(
    data_hash: &[u8; 32],
    program_id_field: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[data_hash.as_slice(), program_id_field.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
