use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use spl_token_2022_interface::{
    extension::{BaseStateWithExtensions, ExtensionType, PodStateWithExtensions},
    pod::{PodAccount, PodMint},
};
use zolana_interface::{error::ShieldedPoolError, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};

#[derive(Clone, Copy)]
pub struct ValidatedTokenMint {
    pub token_account_len: usize,
}

pub fn validate_token_mint_for_interface(
    mint: &AccountView,
    token_program: &Address,
) -> Result<ValidatedTokenMint, ProgramError> {
    if !address_eq(token_program, &Address::from(SPL_TOKEN_PROGRAM_ID))
        && !address_eq(token_program, &Address::from(SPL_TOKEN_2022_PROGRAM_ID))
    {
        return Err(ShieldedPoolError::UnsupportedSplTokenProgram.into());
    };

    if !mint.owned_by(token_program) {
        return Err(ShieldedPoolError::InvalidSplTokenMint.into());
    }
    let data = mint
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSplTokenMint)?;

    let state = PodStateWithExtensions::<PodMint>::unpack(&data)
        .map_err(|_| ShieldedPoolError::InvalidSplTokenMint)?;
    if !bool::from(state.base.is_initialized) {
        return Err(ShieldedPoolError::InvalidSplTokenMint.into());
    }
    let extension_types = state
        .get_extension_types()
        .map_err(|_| ShieldedPoolError::InvalidSplTokenMint)?;
    if !extension_types.iter().all(is_allowed_mint_extension) {
        return Err(ShieldedPoolError::UnsupportedToken2022Extension.into());
    }
    let account_extensions = ExtensionType::get_required_init_account_extensions(&extension_types);
    let token_account_len =
        ExtensionType::try_calculate_account_len::<PodAccount>(&account_extensions)
            .map_err(|_| ShieldedPoolError::InvalidSplTokenMint)?;

    Ok(ValidatedTokenMint { token_account_len })
}

#[inline(always)]
fn is_allowed_mint_extension(extension: &ExtensionType) -> bool {
    matches!(
        extension,
        ExtensionType::InterestBearingConfig
            | ExtensionType::MetadataPointer
            | ExtensionType::TokenMetadata
            | ExtensionType::GroupPointer
            | ExtensionType::TokenGroup
            | ExtensionType::GroupMemberPointer
            | ExtensionType::TokenGroupMember
            | ExtensionType::ScaledUiAmount
            | ExtensionType::ConfidentialTransferMint
            | ExtensionType::ConfidentialTransferFeeConfig
            | ExtensionType::ConfidentialMintBurn
            | ExtensionType::TransferFeeConfig
    )
}
