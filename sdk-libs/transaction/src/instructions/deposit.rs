//! A public deposit into a wallet's private balance.

use zolana_keypair::ShieldedAddress;
use zolana_program::instruction::{AssetDeposit, DepositAsset};

use crate::error::TransactionError;

/// The entry of a [`Deposit`](zolana_program::instruction::Deposit) batch that
/// pays `amount` of `asset` into `recipient`'s private balance.
///
/// The output is owned by `recipient`'s owner hash and tagged with its viewing
/// key: that tag is how the recipient's wallet finds the output without
/// knowing the depositor.
pub fn deposit_to(
    asset: DepositAsset,
    amount: u64,
    recipient: &ShieldedAddress,
) -> Result<AssetDeposit, TransactionError> {
    Ok(AssetDeposit {
        asset,
        view_tag: recipient.viewing_pubkey.x(),
        owner: recipient.owner_hash()?,
        amount,
        memo: None,
    })
}
