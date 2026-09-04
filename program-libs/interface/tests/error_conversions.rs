#![cfg(feature = "tree")]

//! Table pins for the error conversions: every `InterfaceError` and
//! `TreeError` variant maps to an exact `ShieldedPoolError` code, including
//! the catch-all arms. A new variant without an explicit arm falls into the
//! catch-all by construction — the per-variant rows here make that visible
//! instead of silent.

use zolana_interface::error::{InterfaceError, ShieldedPoolError};
use zolana_tree::TreeError;

#[test]
fn interface_error_conversions_are_stable() {
    let table = [
        (
            InterfaceError::InvalidDiscriminator,
            ShieldedPoolError::InvalidProtocolConfig as u32,
        ),
        (
            InterfaceError::Unauthorized,
            ShieldedPoolError::UnauthorizedCaller as u32,
        ),
        (
            InterfaceError::InvalidAccountData,
            ShieldedPoolError::InvalidSplAssetRegistry as u32,
        ),
        (
            InterfaceError::InvalidProtocolConfigData,
            ShieldedPoolError::InvalidProtocolConfig as u32,
        ),
    ];
    for (variant, want) in table {
        assert_eq!(ShieldedPoolError::from(variant) as u32, want, "{variant:?}");
    }
}

#[test]
fn tree_error_conversions_are_stable() {
    // Named arms.
    assert_eq!(
        ShieldedPoolError::from(TreeError::Paused) as u32,
        ShieldedPoolError::TreePaused as u32
    );
    assert_eq!(
        ShieldedPoolError::from(TreeError::TreeIsFull) as u32,
        ShieldedPoolError::StateAppendFailed as u32
    );
    assert_eq!(
        ShieldedPoolError::from(TreeError::FeeOverflow) as u32,
        ShieldedPoolError::InvalidForesterFee as u32
    );

    // Every other variant falls into the catch-all (7001), enumerated
    // explicitly so a future variant's mapping is a deliberate choice.
    let catch_all = [
        TreeError::InvalidBufferSize,
        TreeError::HeightTooLarge,
        TreeError::Deserialize,
        TreeError::NullifierInit,
        TreeError::AlreadyInitialized,
        TreeError::InvalidOwner,
        TreeError::NotWritable,
        TreeError::InvalidDiscriminator,
        TreeError::InvalidRootIndex,
        TreeError::Borrowed,
        TreeError::InvalidCapacity,
        TreeError::Hash,
    ];
    for variant in catch_all {
        assert_eq!(
            ShieldedPoolError::from(variant) as u32,
            ShieldedPoolError::InvalidTreeAccounts as u32,
            "{variant:?} must hit the catch-all"
        );
    }
}
