use light_array_map::ArrayMap;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    event::DepositWithdraw,
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

#[profile]
pub fn process_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data =
        DepositIxData::deserialize(data).map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    process_deposit_internal::<false>(accounts, &data.assets, data.deposits, None)
}

pub fn process_zone_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = ZoneDepositIxData::deserialize(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    process_deposit_internal::<true>(
        accounts,
        &[data.asset],
        vec![DepositEntry {
            asset_index: 0,
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            amount: data.amount,
            utxo_data: data.utxo_data,
            memo: data.memo,
        }],
        Some(ZoneData {
            data_hash: data.zone_data_hash,
            data: data.zone_data,
        }),
    )
}

fn process_deposit_internal<const HAS_ZONE: bool>(
    accounts: &mut [AccountView],
    assets: &[DepositAssetKind],
    entries: Vec<DepositEntry>,
    mut zone: Option<ZoneData>,
) -> ProgramResult {
    if entries.is_empty() {
        return Err(ShieldedPoolError::EmptyDepositBatch.into());
    }

    let (parsed, zone_program_id) =
        DepositAccounts::validate_and_parse::<HAS_ZONE>(&crate::ID, accounts, assets)?;

    let zero = [0u8; 32];
    // The zone binding is per instruction, not per entry: the zone rail carries
    // exactly one entry, so every appended UTXO shares one `zone_hash`.
    let zone_hash = {
        let (zone_data_hash, zone_id_field) = match (&zone, &zone_program_id) {
            (Some(zone), Some(program_id)) => (zone.data_hash, solana_pk_hash(program_id)?),
            _ => (zero, zero),
        };
        hash_with_program_id(&zone_data_hash, &zone_id_field)?
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

    for entry in entries {
        let group = parsed
            .groups
            .get(usize::from(entry.asset_index))
            .ok_or(ShieldedPoolError::InvalidDepositAssetIndex)?;

        let data_hash = match &entry.utxo_data {
            Some(utxo_data) => utxo_data.data_hash,
            None => zero,
        };
        let mut blinding = [0u8; 32];
        blinding[1..].copy_from_slice(&entry.blinding);
        let owner_utxo_hash = Poseidon::hashv(&[entry.owner.as_slice(), blinding.as_slice()])
            .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        let utxo_hash = Poseidon::hashv(&[
            UTXO_DOMAIN_FIELD.as_slice(),
            group.asset_field.as_slice(),
            field_from_u64(entry.amount).as_slice(),
            data_hash.as_slice(),
            zone_hash.as_slice(),
            owner_utxo_hash.as_slice(),
        ])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        utxo_hashes.push(utxo_hash);

        match asset_sums.get_mut_by_key(&entry.asset_index) {
            Some(total) => {
                *total = total
                    .checked_add(entry.amount)
                    .ok_or(ShieldedPoolError::DepositAmountOverflow)?;
            }
            None => {
                asset_sums.insert(
                    entry.asset_index,
                    entry.amount,
                    ShieldedPoolError::TooManyDepositAssets,
                )?;
            }
        }

        outputs.push(proofless_output_utxo(
            entry,
            zone.take(),
            ProoflessOutputCtx {
                utxo_hash,
                asset: group.asset,
                zone_program_id,
            },
        ));
    }

    // One batch append: only the last leaf hashes up to the root, so a batch
    // costs one root recomputation instead of one per entry.
    tree.utxo_tree().append_batch(utxo_hashes.iter());
    drop(tree);

    // Every settlement group must be funded by at least one entry; unused
    // groups would otherwise pass validation without settling.
    if asset_sums.len() != parsed.groups.len() {
        return Err(ShieldedPoolError::UnreferencedDepositAsset.into());
    }

    let mut deposit_withdraws = Vec::with_capacity(asset_sums.len());
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
                deposit_withdraws.push(DepositWithdraw {
                    is_deposit: true,
                    amount: *total,
                    asset: None,
                });
            }
            Settlement::Spl(spl) => {
                if *total > 0 {
                    settle_spl(spl, *total)?;
                }
                deposit_withdraws.push(DepositWithdraw {
                    is_deposit: true,
                    amount: *total,
                    asset: Some(group.asset),
                });
            }
        }
    }

    emit_deposit_event(DepositEvent {
        outputs,
        deposit_withdraws,
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
