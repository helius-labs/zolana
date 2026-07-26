use light_array_map::ArrayMap;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    event::Movement,
    instruction::{
        DepositAssetKind, DepositEntry, DepositIxData, ZoneDepositIxData, MAX_DEPOSIT_ASSETS,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::{
    account::DepositAccounts,
    event::{emit_deposit_event, proofless_output_utxo, DepositEvent, ProoflessOutputCtx},
};
use crate::instructions::{
    hash::{field_from_u64, solana_pk_hash, UTXO_DOMAIN_FIELD},
    settlement::{settle_sol, settle_spl, Settlement},
};

pub(crate) struct ZoneData {
    pub data_hash: [u8; 32],
    pub data: Vec<u8>,
}

struct ProcessingEntry {
    deposit: DepositEntry,
    zone: Option<ZoneData>,
}

#[profile]
pub fn process_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data =
        DepositIxData::deserialize(data).map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let entries = data
        .deposits
        .into_iter()
        .map(|deposit| ProcessingEntry {
            deposit,
            zone: None,
        })
        .collect();
    process_deposit_internal::<false>(accounts, &data.assets, entries)
}

pub fn process_zone_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = ZoneDepositIxData::deserialize(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let entries = data
        .deposits
        .into_iter()
        .map(|entry| ProcessingEntry {
            deposit: entry.deposit,
            zone: Some(ZoneData {
                data_hash: entry.zone_data_hash,
                data: entry.zone_data,
            }),
        })
        .collect();
    process_deposit_internal::<true>(accounts, &data.assets, entries)
}

fn process_deposit_internal<const HAS_ZONE: bool>(
    accounts: &mut [AccountView],
    assets: &[DepositAssetKind],
    entries: Vec<ProcessingEntry>,
) -> ProgramResult {
    if entries.is_empty() {
        return Err(ShieldedPoolError::EmptyDepositBatch.into());
    }

    let (parsed, zone_program_id) =
        DepositAccounts::validate_and_parse::<HAS_ZONE>(&crate::ID, accounts, assets)?;

    let zero = [0u8; 32];
    let zone_program_id_field = match &zone_program_id {
        Some(program_id) => solana_pk_hash(program_id)?,
        None => zero,
    };
    let mut output_tree = [0u8; 32];
    output_tree.copy_from_slice(parsed.tree.address().as_ref());

    let mut asset_sums: ArrayMap<u8, u64, MAX_DEPOSIT_ASSETS> = ArrayMap::new();
    let mut outputs = Vec::with_capacity(entries.len());
    let mut utxo_hashes = Vec::with_capacity(entries.len());

    // Load the tree before hashing so a paused tree costs no Poseidon work, and
    // keep the one borrow until the batch append below (never load it twice).
    let mut tree =
        TreeAccount::from_account_view_mut(parsed.tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(ShieldedPoolError::from)?;
    let first_output_leaf_index = tree.utxo_tree().next_index();

    for processing_entry in entries {
        let ProcessingEntry { deposit, zone } = processing_entry;
        let group = parsed
            .groups
            .get(usize::from(deposit.asset_index))
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;

        let data_hash = match &deposit.utxo_data {
            Some(utxo_data) => utxo_data.data_hash,
            None => zero,
        };
        let owner_utxo_hash = Poseidon::hashv(&[
            deposit.owner.as_slice(),
            deposit.blinding.as_slice(),
        ])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        let zone_data_hash = match &zone {
            Some(zone) => zone.data_hash,
            None => zero,
        };
        let zone_hash = hash_with_program_id(&zone_data_hash, &zone_program_id_field)?;
        let utxo_hash = Poseidon::hashv(&[
            UTXO_DOMAIN_FIELD.as_slice(),
            group.asset_field.as_slice(),
            field_from_u64(deposit.amount).as_slice(),
            data_hash.as_slice(),
            zone_hash.as_slice(),
            owner_utxo_hash.as_slice(),
        ])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        utxo_hashes.push(utxo_hash);

        match asset_sums.get_mut_by_key(&deposit.asset_index) {
            Some(total) => {
                *total = total
                    .checked_add(deposit.amount)
                    .ok_or(ShieldedPoolError::DepositAmountOverflow)?;
            }
            None => {
                asset_sums.insert(
                    deposit.asset_index,
                    deposit.amount,
                    ShieldedPoolError::TooManyDepositAssets,
                )?;
            }
        }

        outputs.push(proofless_output_utxo(
            deposit,
            zone,
            ProoflessOutputCtx {
                utxo_hash,
                asset: group.asset,
                zone_program_id,
            },
        ));
    }

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

    let mut movements = Vec::with_capacity(asset_sums.len());
    for slot in 0..asset_sums.len() {
        let (asset_index, total) = asset_sums
            .get_by_index(slot)
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;
        let group = parsed
            .groups
            .get(usize::from(*asset_index))
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;

        match &group.settlement {
            Settlement::Sol(sol) => {
                if *total > 0 {
                    settle_sol(sol, *total, true)?;
                }
                movements.push(Movement {
                    is_deposit: true,
                    amount: *total,
                    asset: None,
                });
            }
            Settlement::Spl(spl) => {
                if *total > 0 {
                    settle_spl(spl, *total)?;
                }
                movements.push(Movement {
                    is_deposit: true,
                    amount: *total,
                    asset: Some(group.asset),
                });
            }
        }
    }

    emit_deposit_event(DepositEvent {
        outputs,
        movements,
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
