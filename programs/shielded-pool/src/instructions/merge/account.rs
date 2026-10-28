use super::cache::{parse_cache_accounts, MergeCacheAccounts};
use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use spr_account_checks::AccountIterator;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    error::ShieldedPoolError, instruction::instruction_data::merge_transact::MAX_MERGE_INPUTS,
};
use spr_user_registry_interface::{
    state::{MergeEncryptionScheme, UserRecord},
    USER_RECORD_SEED, USER_REGISTRY_PROGRAM_ID,
};

/// Validated accounts for `merge_transact`, in loader order: `input_tree` and
/// `output_tree` (writable), `payer` (signer, pays fees), `user_record`
/// (read-only), System Program, the program account (for the `emit_event`
/// self-CPI), then one writable nullifier PDA per input and, when the merge
/// writes a cache, the writable cache followed by its writer (signer).
pub struct MergeTransactAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub user_record: &'a AccountView,
    pub nullifier_pdas: ArrayVec<&'a mut AccountView, MAX_MERGE_INPUTS>,
    pub cache: Option<MergeCacheAccounts<'a>>,
}

impl<'a> MergeTransactAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        input_count: usize,
        cache_slot: Option<u8>,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        let payer = iter.next_signer("payer")?;
        let user_record = iter.next_account("user_record")?;
        let system_program = iter.next_account("system_program")?;
        if !pinocchio_system::check_id(system_program.address()) {
            return Err(ShieldedPoolError::InvalidSystemProgram.into());
        }
        let shielded_pool_program = iter.next_account("shielded_pool_program")?;
        if !address_eq(shielded_pool_program.address(), &crate::ID) {
            return Err(ProgramError::IncorrectProgramId);
        }
        let mut nullifier_pdas = ArrayVec::new();
        for _ in 0..input_count {
            nullifier_pdas
                .try_push(iter.next_mut("nullifier_pda")?)
                .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        }
        let cache = parse_cache_accounts(iter, cache_slot)?;
        Ok(Self {
            cache,
            input_tree,
            output_tree,
            payer,
            user_record,
            nullifier_pdas,
        })
    }
}

/// The registry-derived owner identity public inputs: the already-derived
/// tagged owner identity of the signing key and its owner-pubkey index tag.
/// Feeding these into the recomputed public-input hash binds the proof to the
/// registered key.
///
/// `signing_view_tag` is the owner-pubkey index tag for the merged output (the
/// confidential default-ring tag): the full ed25519 key.
pub struct UserPkFields {
    pub signing_pk_field: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub signing_view_tag: [u8; 32],
    pub merge_encryption: MergeEncryptionScheme,
}

/// Load and validate the `user_record`: owned by the registry program, stored at
/// the canonical PDA for its owner, and containing a valid `UserRecord`
/// discriminator/body. Returns the per-user `merge_encryption` scheme alongside
/// the owner identity; the processor rejects the merge when it is `Disabled` or
/// differs from the instruction's scheme. A Solana owner derives
/// `signing_pk_field` as the tagged Solana identity of the registry account
/// `owner` (ed25519).
#[inline(never)]
pub fn load_user_record(account: &AccountView) -> Result<UserPkFields, ProgramError> {
    let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
    if !account.owned_by(&registry_id) {
        return Err(ShieldedPoolError::InvalidUserRecord.into());
    }
    let data = account
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::InvalidUserRecord))?;
    let record = UserRecord::try_from_account_data(&data)
        .map_err(caused_by(ShieldedPoolError::InvalidUserRecord))?;
    let (expected_record, expected_bump) =
        Address::derive_program_address(&[USER_RECORD_SEED, record.owner.as_ref()], &registry_id)
            .ok_or(ShieldedPoolError::InvalidUserRecord)?;
    if account.address() != &expected_record || record.bump != expected_bump {
        return Err(ShieldedPoolError::InvalidUserRecord.into());
    }
    let merge_encryption = record.merge_encryption;
    let signing_view_tag = record.owner.to_bytes();
    let signing_pk_field = solana_owner_identity(&signing_view_tag)?;
    Ok(UserPkFields {
        signing_pk_field,
        nullifier_pk: record.nullifier_pubkey,
        signing_view_tag,
        merge_encryption,
    })
}
