use pinocchio::{error::ProgramError, AccountView, Address};
use shielded_pool_program::instructions::create_spl_interface::validate::validate_token_mint_for_interface;
use spl_token_2022_interface::{
    extension::{
        confidential_mint_burn::ConfidentialMintBurn,
        confidential_transfer::ConfidentialTransferMint,
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        metadata_pointer::MetadataPointer, permanent_delegate::PermanentDelegate,
        transfer_fee::TransferFeeConfig, BaseStateWithExtensionsMut, ExtensionType,
        PodStateWithExtensionsMut,
    },
    pod::PodMint,
};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    error::ShieldedPoolError, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_LEN,
};

const MINT_ADDRESS: [u8; 32] = [7; 32];

fn token_2022_mint_data(extension_types: &[ExtensionType]) -> Vec<u8> {
    let len = ExtensionType::try_calculate_account_len::<PodMint>(extension_types).unwrap();
    vec![0; len]
}

fn token_2022_mint_with_metadata_pointer() -> AccountView {
    let mut data = token_2022_mint_data(&[ExtensionType::MetadataPointer]);
    let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut data).unwrap();
    state.init_extension::<MetadataPointer>(false).unwrap();
    state.base.is_initialized = true.into();
    state.init_account_type().unwrap();
    get_account_view(
        MINT_ADDRESS,
        SPL_TOKEN_2022_PROGRAM_ID,
        false,
        false,
        false,
        data,
    )
}

fn token_2022_mint_with_transfer_fee() -> AccountView {
    let mut data = token_2022_mint_data(&[ExtensionType::TransferFeeConfig]);
    let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut data).unwrap();
    state.init_extension::<TransferFeeConfig>(false).unwrap();
    state.base.is_initialized = true.into();
    state.init_account_type().unwrap();
    get_account_view(
        MINT_ADDRESS,
        SPL_TOKEN_2022_PROGRAM_ID,
        false,
        false,
        false,
        data,
    )
}

fn token_2022_mint_with_safe_confidential_extensions() -> AccountView {
    let extension_types = [
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialMintBurn,
    ];
    let mut data = token_2022_mint_data(&extension_types);
    let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut data).unwrap();
    state
        .init_extension::<ConfidentialTransferMint>(false)
        .unwrap();
    state.init_extension::<ConfidentialMintBurn>(false).unwrap();
    state.base.is_initialized = true.into();
    state.init_account_type().unwrap();
    get_account_view(
        MINT_ADDRESS,
        SPL_TOKEN_2022_PROGRAM_ID,
        false,
        false,
        false,
        data,
    )
}

fn token_2022_mint_with_confidential_transfer_fee() -> AccountView {
    let extension_types = [
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::TransferFeeConfig,
        ExtensionType::ConfidentialTransferFeeConfig,
    ];
    let mut data = token_2022_mint_data(&extension_types);
    let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut data).unwrap();
    state
        .init_extension::<ConfidentialTransferMint>(false)
        .unwrap();
    state.init_extension::<TransferFeeConfig>(false).unwrap();
    state
        .init_extension::<ConfidentialTransferFeeConfig>(false)
        .unwrap();
    state.base.is_initialized = true.into();
    state.init_account_type().unwrap();
    get_account_view(
        MINT_ADDRESS,
        SPL_TOKEN_2022_PROGRAM_ID,
        false,
        false,
        false,
        data,
    )
}

fn token_2022_mint_with_permanent_delegate() -> AccountView {
    let mut data = token_2022_mint_data(&[ExtensionType::PermanentDelegate]);
    let mut state = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut data).unwrap();
    state.init_extension::<PermanentDelegate>(false).unwrap();
    state.base.is_initialized = true.into();
    state.init_account_type().unwrap();
    get_account_view(
        MINT_ADDRESS,
        SPL_TOKEN_2022_PROGRAM_ID,
        false,
        false,
        false,
        data,
    )
}

#[test]
fn accepts_safe_token_2022_mint_extensions() {
    let mint = token_2022_mint_with_metadata_pointer();
    let validated =
        validate_token_mint_for_interface(&mint, &Address::from(SPL_TOKEN_2022_PROGRAM_ID))
            .unwrap();

    assert_eq!(validated.token_account_len, SPL_TOKEN_ACCOUNT_LEN);
}

#[test]
fn rejects_transfer_fee_config() {
    let mint = token_2022_mint_with_transfer_fee();
    let error =
        match validate_token_mint_for_interface(&mint, &Address::from(SPL_TOKEN_2022_PROGRAM_ID)) {
            Ok(_) => panic!("transfer-fee mints must be rejected"),
            Err(error) => error,
        };

    assert_eq!(
        error,
        ProgramError::Custom(ShieldedPoolError::UnsupportedToken2022Extension as u32)
    );
}

#[test]
fn accepts_confidential_token_extensions() {
    let mint = token_2022_mint_with_safe_confidential_extensions();
    let validated =
        validate_token_mint_for_interface(&mint, &Address::from(SPL_TOKEN_2022_PROGRAM_ID))
            .unwrap();

    assert_eq!(validated.token_account_len, SPL_TOKEN_ACCOUNT_LEN);
}

#[test]
fn rejects_confidential_transfer_fee_config() {
    let mint = token_2022_mint_with_confidential_transfer_fee();
    let error =
        match validate_token_mint_for_interface(&mint, &Address::from(SPL_TOKEN_2022_PROGRAM_ID)) {
            Ok(_) => panic!("confidential transfer-fee mints must be rejected"),
            Err(error) => error,
        };

    assert_eq!(
        error,
        ProgramError::Custom(ShieldedPoolError::UnsupportedToken2022Extension as u32)
    );
}

#[test]
fn rejects_unsupported_token_2022_extensions() {
    let mint = token_2022_mint_with_permanent_delegate();
    let error =
        match validate_token_mint_for_interface(&mint, &Address::from(SPL_TOKEN_2022_PROGRAM_ID)) {
            Ok(_) => panic!("permanent-delegate mints must be rejected"),
            Err(error) => error,
        };

    assert_eq!(
        error,
        ProgramError::Custom(ShieldedPoolError::UnsupportedToken2022Extension as u32)
    );
}
