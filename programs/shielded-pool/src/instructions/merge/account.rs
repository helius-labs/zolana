use light_account_checks::AccountIterator;
use pinocchio::{address::Address, error::ProgramError, AccountView};
use zolana_interface::error::ShieldedPoolError;
use zolana_user_registry_interface::{state::UserRecord, USER_REGISTRY_PROGRAM_ID};

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

/// The two registry-derived owner identity public inputs: `pk_field` of the
/// signing P256 key and of the viewing key. Feeding these directly into the
/// recomputed public-input hash binds the proof to the registered keys without a
/// separate compare.
pub struct UserPkFields {
    pub signing: [u8; 33],
    pub viewing: [u8; 33],
}

/// Load and validate the `user_record`: owned by the registry program, valid
/// `UserRecord` discriminator/body, merge service opted in, and a registered P256
/// signing key. Returns the compressed signing and viewing keys for `pk_field`.
#[inline(never)]
pub fn load_user_record(account: &AccountView) -> Result<UserPkFields, ProgramError> {
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
    let signing = record
        .owner_p256
        .ok_or(ShieldedPoolError::InvalidUserRecord)?;
    Ok(UserPkFields {
        signing,
        viewing: record.viewing_pubkey,
    })
}
