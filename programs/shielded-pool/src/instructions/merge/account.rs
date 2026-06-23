use pinocchio::{address::Address, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, merge_utils::pk_field_compressed};
use zolana_user_registry_interface::{state::UserRecord, USER_REGISTRY_PROGRAM_ID};

use crate::instructions::hash::solana_pk_hash;

/// Validated accounts for `merge_transact`, in loader order: `tree` (writable),
/// `protocol_config` (read-only), `payer` (signer), `user_record` (read-only).
pub struct MergeTransactAccounts<'a> {
    pub tree: &'a mut AccountView,
    pub protocol_config: &'a AccountView,
    pub payer: &'a AccountView,
    pub user_record: &'a AccountView,
}

impl<'a> MergeTransactAccounts<'a> {
    pub fn validate_and_parse(
        _program_id: &Address,
        accounts: &'a mut [AccountView],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let tree = iter.next_mut("tree")?;
        let protocol_config = iter.next_account("protocol_config")?;
        let payer = iter.next_signer("payer")?;
        let user_record = iter.next_account("user_record")?;
        Ok(Self {
            tree,
            protocol_config,
            payer,
            user_record,
        })
    }
}

/// The two registry-derived owner identity public inputs: the already-derived
/// `pk_field` of the signing key (rail-selected) and the compressed viewing key
/// (its `pk_field` is computed by the processor). Feeding these into the
/// recomputed public-input hash binds the proof to the registered keys.
pub struct UserPkFields {
    pub signing_pk_field: [u8; 32],
    pub viewing: [u8; 33],
}

/// Load and validate the `user_record`: owned by the registry program, valid
/// `UserRecord` discriminator/body, and merge service opted in. The owner identity
/// is rail-selected by `eddsa_owner`: a Solana owner derives `signing_pk_field`
/// from the registry account `owner` (ed25519), a P256 owner from `owner_p256`.
#[inline(never)]
pub fn load_user_record(
    account: &AccountView,
    eddsa_owner: bool,
) -> Result<UserPkFields, ProgramError> {
    let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
    if !account.owned_by(&registry_id) {
        return Err(ShieldedPoolError::InvalidUserRecord.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidUserRecord)?;
    let record = UserRecord::try_from_account_data(&data)
        .map_err(|_| ShieldedPoolError::InvalidUserRecord)?;
    if !record.merge_service {
        return Err(ShieldedPoolError::MergeServiceDisabled.into());
    }
    let signing_pk_field = if eddsa_owner {
        solana_pk_hash(&record.owner)?
    } else {
        let owner_p256 = record
            .owner_p256
            .ok_or(ShieldedPoolError::InvalidUserRecord)?;
        pk_field_compressed(&owner_p256).map_err(|_| ShieldedPoolError::InvalidUserRecord)?
    };
    Ok(UserPkFields {
        signing_pk_field,
        viewing: record.viewing_pubkey,
    })
}
